use std::mem::size_of;

use windows::{
    core::PCWSTR,
    w,
    Win32::{
        Foundation::{self, GetLastError, BOOL, ERROR_NO_TOKEN, ERROR_SUCCESS},
        Security::{
            AdjustTokenPrivileges, ImpersonateSelf, LookupPrivilegeValueW, SecurityImpersonation,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
            TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY,
        },
        System::Threading,
    },
};

fn main() {
    println!("Hello, world!");
    let ps: u32;
    unsafe {
        ps = Threading::GetCurrentProcessId();
    }

    println!("PID is{}", ps);

    // if (GrantSelfSeDebug()) {
    //     Interface::Log(Interface::VerbosityLevel::Debug, "... successfully granted SeDebug privilege to self\r\n");
    // }
    // else {
    //     Interface::Log(Interface::VerbosityLevel::Surface, "... failed to grant SeDebug privilege to self. Certain processes will be inaccessible.\r\n");
    // }

    // if ((qwOptFlags & PROCESS_ENUM_FLAG_MEMDUMP)) {
    //     MemDump::Initialize();
    // }
}

fn grant_self_se_debug() -> bool {
    unsafe {
        let mut hdl = Foundation::HANDLE::default();
        let rhdl = &mut hdl as *mut Foundation::HANDLE;

        let status = Threading::OpenThreadToken(
            Threading::GetCurrentThread(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            false,
            rhdl,
        );
        if !bool::from(status) {
            if GetLastError() == ERROR_NO_TOKEN {
                let imp = ImpersonateSelf(SecurityImpersonation);
                if !(bool::from(imp)) {
                    return false;
                }

                let status = Threading::OpenThreadToken(
                    Threading::GetCurrentThread(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                    false,
                    rhdl,
                );

                if !(bool::from(status)) {
                    return false;
                }
            } else {
                return false;
            };

            let setPriv = set_privilege(hdl, w!("SeDebugPrivilege"), true);
        }
    }
    return true;

    // bool GrantSelfSeDebug() {
    //     HANDLE hToken;

    //     if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
    //         if (GetLastError() == ERROR_NO_TOKEN) {
    //             if (!ImpersonateSelf(SecurityImpersonation)) {
    //                 return false;
    //             }

    //             if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
    //                 return false;
    //             }
    //         }
    //         else {
    //             return false;
    //         }
    //     }

    //     if (!SetPrivilege(hToken, L"SeDebugPrivilege", TRUE)) {
    //         CloseHandle(hToken);
    //         return false;
    //     }

    //     CloseHandle(hToken);
    //     return true;
    // }
}

fn set_privilege<P0>(h_token: Foundation::HANDLE, privilige: P0, enable_privilige: bool) -> bool
where
    P0: ::std::convert::Into<::windows::core::InParam<::windows::core::PCWSTR>>,
{
    let mut TokenPrivs = TOKEN_PRIVILEGES::default();
    let mut TokenPrivsPrev = TOKEN_PRIVILEGES::default();
    let mut luid = Foundation::LUID::default();

    unsafe {
        // Retrieves the locally unique identifier (LUID) used on a specified system to locally represent the specified privilege name.
        let res = LookupPrivilegeValueW(
            PCWSTR::null(),
            privilige,
            &mut luid as *mut Foundation::LUID,
        );

        // We found the Luid
        if bool::from(res) {
            TokenPrivs.PrivilegeCount = 1;
            TokenPrivs.Privileges[0].Luid = luid;
            TokenPrivs.Privileges[0].Attributes = TOKEN_PRIVILEGES_ATTRIBUTES::default();
            let mut buffSize: u32 = std::mem::size_of::<TOKEN_PRIVILEGES>() as u32;

            // The AdjustTokenPrivileges function enables or disables privileges in the specified access token. 
            // Enabling or disabling privileges in an access token requires TOKEN_ADJUST_PRIVILEGES access.
            // 
            let adj = AdjustTokenPrivileges(
                h_token,
                BOOL::from(false),
                Some(&TokenPrivs),
                buffSize,
                Some(&mut TokenPrivsPrev as *mut TOKEN_PRIVILEGES),
                Some(&mut buffSize as *mut u32),
            );

            // Sucessfully adjusted privs
            if GetLastError() == ERROR_SUCCESS {
                TokenPrivsPrev.PrivilegeCount = 1;
                TokenPrivsPrev.Privileges[0].Luid = luid;

                if enable_privilige {
                    TokenPrivsPrev.Privileges[0].Attributes |= SE_PRIVILEGE_ENABLED;
                // Add the `SE_PRIVILEGE_ENABLED` to the attributes
                } else {
                    // I have no idea what this is doing!
                    TokenPrivsPrev.Privileges[0].Attributes =
                        windows::Win32::Security::TOKEN_PRIVILEGES_ATTRIBUTES(
                            TokenPrivsPrev.Privileges[0].Attributes.0
                                ^ (SE_PRIVILEGE_ENABLED & TokenPrivsPrev.Privileges[0].Attributes)
                                    .0,
                        );
                }
            }
        }
    }
    // bool SetPrivilege(HANDLE hToken, const wchar_t *Privilege, bool bEnablePrivilege) {
    // 	assert(Privilege != nullptr);

    // 	TOKEN_PRIVILEGES TokenPrivs = { 0 };
    // 	LUID Luid;
    // 	TOKEN_PRIVILEGES TokenPrivPrev = { 0 };
    // 	uint32_t dwPrevSize = sizeof(TOKEN_PRIVILEGES);

    // 	if (LookupPrivilegeValueW(nullptr, Privilege, &Luid)) {
    // 		TokenPrivs.PrivilegeCount = 1;
    // 		TokenPrivs.Privileges[0].Luid = Luid;
    // 		TokenPrivs.Privileges[0].Attributes = 0;

    // 		AdjustTokenPrivileges(hToken, false, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), &TokenPrivPrev, reinterpret_cast<DWORD *>(&dwPrevSize));

    // 		if (GetLastError() == ERROR_SUCCESS) {
    // 			TokenPrivPrev.PrivilegeCount = 1;
    // 			TokenPrivPrev.Privileges[0].Luid = Luid;

    // 			if (bEnablePrivilege) {
    // 				TokenPrivPrev.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
    // 			}
    // 			else {
    // 				TokenPrivPrev.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & TokenPrivPrev.Privileges[0].Attributes);
    // 			}

    // 			AdjustTokenPrivileges(hToken, false, &TokenPrivPrev, dwPrevSize, nullptr, nullptr);
    // 			if (GetLastError() == ERROR_SUCCESS) return true;
    // 		}
    // 	}

    // 	return false;
    // }
    return false;
}
