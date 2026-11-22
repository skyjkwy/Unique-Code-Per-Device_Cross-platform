#include <windows.h>
#include <stdio.h>

#include "license_dll.h"

void StaticLinkExample(void) {
    printf("=== 静态链接示例 ===\n\n");

    printf("1. 初始化授权系统...\n");
    int ret = License_Init(NULL);
    if (ret != LICENSE_OK) {
        printf("   初始化失败: %d\n", ret);
        return;
    }
    printf("   初始化成功!\n\n");

    printf("2. 获取机器码...\n");
    char machine_code[65] = {0};
    ret = License_GetMachineCode(machine_code, sizeof(machine_code));
    if (ret == LICENSE_OK) {
        printf("   机器码: %s\n\n", machine_code);
    }

    printf("3. 检查授权状态...\n");
    BOOL activated = License_IsActivated();
    printf("   授权状态: %s\n\n", activated ? "已激活" : "未激活");

    printf("4. 获取授权详情...\n");
    LicenseInfo info;
    ret = License_GetInfo(&info);
    if (ret == LICENSE_OK) {
        printf("   状态: %d\n", info.status);
        printf("   用户名: %s\n", info.username);
        printf("   邮箱: %s\n", info.email);
        printf("   过期时间: %u\n", info.expire_time);
        printf("   当前时间: %u\n", info.current_time);
        printf("   剩余天数: %u\n\n", info.remaining_days);
    }

    printf("5. 验证授权有效性...\n");
    BOOL valid = License_Verify();
    printf("   验证结果: %s\n\n", valid ? "有效" : "无效");

    if (!activated) {
        printf("6. 显示激活对话框...\n");
        License_ShowActivationDialog(NULL);
    }

    printf("7. 关闭授权系统...\n");
    License_Shutdown();
    printf("   已关闭!\n\n");
}

void DynamicLoadExample(void) {
    printf("=== 动态加载示例 ===\n\n");

    printf("1. 加载 license.dll...\n");
    HMODULE hDll = LoadLibraryA("license.dll");
    if (!hDll) {
        printf("   加载失败! 请确保 DLL 在同目录下.\n\n");
        return;
    }
    printf("   加载成功!\n\n");

    printf("2. 获取函数地址...\n");
    typedef int (*PFN_License_Init)(const LicenseConfig*);
    typedef void (*PFN_License_Shutdown)(void);
    typedef BOOL (*PFN_License_IsActivated)(void);
    typedef int (*PFN_License_GetMachineCode)(char*, int);

    PFN_License_Init pLicense_Init = (PFN_License_Init)GetProcAddress(hDll, "License_Init");
    PFN_License_Shutdown pLicense_Shutdown = (PFN_License_Shutdown)GetProcAddress(hDll, "License_Shutdown");
    PFN_License_IsActivated pLicense_IsActivated = (PFN_License_IsActivated)GetProcAddress(hDll, "License_IsActivated");
    PFN_License_GetMachineCode pLicense_GetMachineCode = (PFN_License_GetMachineCode)GetProcAddress(hDll, "License_GetMachineCode");

    if (!pLicense_Init || !pLicense_Shutdown || !pLicense_IsActivated || !pLicense_GetMachineCode) {
        printf("   获取函数地址失败!\n");
        FreeLibrary(hDll);
        return;
    }
    printf("   获取成功!\n\n");

    printf("3. 初始化...\n");
    int ret = pLicense_Init(NULL);
    printf("   初始化结果: %s\n\n", ret == LICENSE_OK ? "成功" : "失败");

    printf("4. 获取机器码...\n");
    char machine_code[65] = {0};
    pLicense_GetMachineCode(machine_code, sizeof(machine_code));
    printf("   机器码: %s\n\n", machine_code);

    printf("5. 检查状态...\n");
    BOOL activated = pLicense_IsActivated();
    printf("   状态: %s\n\n", activated ? "已激活" : "未激活");

    printf("6. 关闭并卸载...\n");
    pLicense_Shutdown();
    FreeLibrary(hDll);
    printf("   已卸载!\n\n");
}

void TypicalUsageExample(void) {
    printf("=== 典型使用示例 ===\n\n");

    printf("[程序启动]\n\n");

    License_Init(NULL);

    if (!License_IsActivated()) {
        printf("未授权! 显示激活对话框...\n");
        License_ShowActivationDialog(NULL);

        if (!License_IsActivated()) {
            printf("用户未激活, 退出程序!\n");
            License_Shutdown();
            return;
        }
    }

    LicenseInfo info;
    License_GetInfo(&info);
    printf("欢迎 %s! 您的授权状态: %s\n\n",
           info.username,
           info.status == LICENSE_STATUS_PERMANENT ? "永久授权" :
           (info.status == LICENSE_STATUS_ACTIVATED ? "已激活" : "未知"));

    printf("[主程序运行中...]\n\n");

    printf("[程序退出]\n");
    License_Shutdown();
    printf("已清理!\n");
}

int main(void) {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
    printf("License DLL 测试程序\n");
    printf("====================\n\n");

    int choice;
    do {
        printf("\n请选择测试模式:\n");
        printf("1. 静态链接示例\n");
        printf("2. 动态加载示例\n");
        printf("3. 典型使用示例\n");
        printf("0. 退出\n\n");
        printf("选择: ");

        if (scanf("%d", &choice) != 1) break;

        printf("\n");

        switch (choice) {
            case 1:
                StaticLinkExample();
                break;
            case 2:
                DynamicLoadExample();
                break;
            case 3:
                TypicalUsageExample();
                break;
            case 0:
                printf("退出程序.\n");
                break;
            default:
                printf("无效选择!\n");
        }

        if (choice != 0) {
            printf("\n按回车键继续...");
            getchar();
            getchar();
            system("cls");
        }

    } while (choice != 0);

    return 0;
}
