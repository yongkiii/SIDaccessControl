//출처: https://ezbeat.tistory.com/388 [Library of Ezbeat:티스토리

#include <windows.h>
#include <tchar.h>
#include <aclapi.h>
#include <conio.h>
#include <stdio.h>

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	//로컬고유식별자를 검색하여 지정된 권한 이름을 로컬로 나타내는 함수
	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

//권한을 위임해주는 함수
BOOL TakeOwnership(LPTSTR lpszOwnFile)
{

	BOOL bRetval = FALSE;

	HANDLE hToken = NULL;
	PSID pSIDAdmin = NULL;
	PSID pSIDEveryone = NULL;
	PSID pSIDLocal = NULL;
	PSID pSIDLocal2 = NULL;
	PSID pSIDLocal3 = NULL;
	PACL pACL = NULL;
	//https://driverentry.tistory.com/entry/%EC%84%9C%EB%B9%84%EC%8A%A4-%E3%85%A0%E3%85%A0
	//사용할 SID 생성
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld =
		SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDLocal = SECURITY_NT_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDLocal2 = SECURITY_NT_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDLocal3 = SECURITY_NT_AUTHORITY;

	const int NUM_ACES = 5;
	EXPLICIT_ACCESS ea[NUM_ACES];
	DWORD dwRes;
	//https://learn.microsoft.com/ko-kr/windows/win32/api/securitybaseapi/nf-securitybaseapi-allocateandinitializesid
	// 사용할 DACL을 지정한다. 
	// Everyone 그룹을 위한 SID를 생성한다.
	//https://learn.microsoft.com/ko-kr/windows/win32/secauthz/well-known-sids
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
		SECURITY_WORLD_RID,
		0,
		0, 0, 0, 0, 0, 0,
		&pSIDEveryone))
	{
		printf("AllocateAndInitializeSid (Everyone) error %u\n",
			GetLastError());
		goto Cleanup;
	}

	// BUILIN/Administrators 그룹을 위한 SID를 생성한다.
	if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pSIDAdmin))
	{
		printf("AllocateAndInitializeSid (Admin) error %u\n",
			GetLastError());
		goto Cleanup;
	}
	// BIT 계정을 위한 SID를 생성한다.
	//SID 하위 번호를 넣는 곳 
	// --> 여기 파트에 DB에 저장되어 있는 SID를 가져와 실행 
	if (!AllocateAndInitializeSid(&SIDLocal,5 ,
		SECURITY_NT_NON_UNIQUE,
		851780408,
		2483676611, 415283615, 1007, 0, 0, 0,
		&pSIDLocal))
	{
		
		printf("AllocateAndInitializeSid (Local) error %u\n",
			GetLastError());
		goto Cleanup;
	}
	if (!AllocateAndInitializeSid(&SIDLocal2, 5,
		SECURITY_NT_NON_UNIQUE,
		851780408,
		2483676611, 415283615, 1006, 0, 0, 0,
		&pSIDLocal2))
	{

		printf("AllocateAndInitializeSid (Local) error %u\n",
			GetLastError());
		goto Cleanup;
	}
	if (!AllocateAndInitializeSid(&SIDLocal3, 5,
		SECURITY_NT_NON_UNIQUE,
		851780408,
		2483676611, 415283615, 1008, 0, 0, 0,
		&pSIDLocal3))
	{

		printf("AllocateAndInitializeSid (Local) error %u\n",
			GetLastError());
		goto Cleanup;
	}
	DWORD subAuthorityCount = (DWORD)GetSidSubAuthorityCount(pSIDLocal);

	_tprintf(_T("Subauthority count: %lu\n"), subAuthorityCount);
	DWORD subAuthorityIndex = 4;
	DWORD subAuthorityValue = *GetSidSubAuthority(pSIDLocal, subAuthorityIndex);
	// 결과 출력
	_tprintf(_T("Subauthority at index %lu: %lu\n"), subAuthorityIndex, subAuthorityValue);
	//나머지 공간은 0으로 채워라
	ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

	// Everyone을 read access로 셋한다.
	ea[0].grfAccessPermissions = GENERIC_READ|GENERIC_EXECUTE;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pSIDEveryone; // 여기 구간에 0번 인덱스에 everyone이 들어간다고 알려줌

	// Administrators을 full control로 셋한다.
	ea[1].grfAccessPermissions = GENERIC_ALL;
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[1].Trustee.ptstrName = (LPTSTR)pSIDAdmin;


	//Local 주성를 셋한다.
	//앞단에 
	ea[2].grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
	ea[2].grfAccessMode = GRANT_ACCESS;
	ea[2].grfInheritance = NO_INHERITANCE;
	ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[2].Trustee.ptstrName = (LPTSTR)pSIDLocal;
	//Local 주성를 셋한다.
	ea[3].grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
	ea[3].grfAccessMode = GRANT_ACCESS;
	ea[3].grfInheritance = NO_INHERITANCE;
	ea[3].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[3].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[3].Trustee.ptstrName = (LPTSTR)pSIDLocal2;
	//Local 주성를 셋한다.
	ea[4].grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
	ea[4].grfAccessMode = GRANT_ACCESS;
	ea[4].grfInheritance = NO_INHERITANCE;
	ea[4].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[4].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[4].Trustee.ptstrName = (LPTSTR)pSIDLocal3;


	/*ea[3].grfAccessPermissions = GENERIC_ALL;
	ea[3].grfAccessMode = GRANT_ACCESS;
	ea[3].grfInheritance = NO_INHERITANCE;
	ea[3].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[3].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[3].Trustee.ptstrName = (LPTSTR)pSIDLocal;*/



	if (ERROR_SUCCESS != SetEntriesInAcl(NUM_ACES,
		ea,
		NULL,
		&pACL))
	{
		printf("Failed SetEntriesInAcl\n");
		goto Cleanup;
	}

	// 오브젝트의 DACL 수정을 시도한다.
	dwRes = SetNamedSecurityInfo(
		lpszOwnFile,                 // name of the object
		SE_FILE_OBJECT,              // type of object
		DACL_SECURITY_INFORMATION,   // change only the object's DACL
		NULL, NULL,                  // do not change owner or group
		pACL,                        // DACL specified
		NULL);                       // do not change SACL

	if (ERROR_SUCCESS == dwRes)
	{
		printf("Successfully changed DACL\n");
		bRetval = TRUE;
		// 더이상 작업이 필요 없음
		goto Cleanup;
	}
	if (dwRes != ERROR_ACCESS_DENIED)
	{
		printf("First SetNamedSecurityInfo call failed: %u\n",
			dwRes);
		goto Cleanup;
	}


	// 만약 앞 호출이 실패 했다면 접근이 거부되었기 때문이다.
	// SE_TAKE_OWNERSHIP_NAME 권한을 활성화한다. 그리고 오브젝트의 DACL을 다시 셋 한다.

	// 호출한 프로세스의 access token 핸들을 연다.
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES,
		&hToken))
	{
		printf("OpenProcessToken failed: %u\n", GetLastError());
		goto Cleanup;
	}

	// SE_TAKE_OWNERSHIP_NAME 특권을 활성화 시킨다.
	if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE))
	{
		printf("You must be logged on as Administrator.\n");
		goto Cleanup;
	}

	// 오브젝트의 security descriptor에 있는 onwer를 셋한다.
	dwRes = SetNamedSecurityInfo(
		lpszOwnFile,                 // name of the object
		SE_FILE_OBJECT,              // type of object
		OWNER_SECURITY_INFORMATION,  // change only the object's owner
		pSIDAdmin,                   // SID of Administrator group
		NULL,
		NULL,
		NULL);

	if (dwRes != ERROR_SUCCESS)
	{
		printf("Could not set owner. Error: %u\n", dwRes);
		goto Cleanup;
	}

	// SE_TAKE_OWNERSHIP_NAME 특권을 비활성화 시킨다.
	if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, FALSE))
	{
		printf("Failed SetPrivilege call unexpectedly.\n");
		goto Cleanup;
	}

	// 오브젝트의 DACL 수정을 다시 시도한다.
	// 지금은 현재 권한이 파일에 대한 onwer이다.
	dwRes = SetNamedSecurityInfo(
		lpszOwnFile,                 // name of the object
		SE_FILE_OBJECT,              // type of object
		DACL_SECURITY_INFORMATION,   // change only the object's DACL
		NULL, NULL,                  // do not change owner or group
		pACL,                        // DACL specified
		NULL);                       // do not change SACL

	if (dwRes == ERROR_SUCCESS)
	{
		printf("Successfully changed DACL\n");
		bRetval = TRUE;
	}
	else
	{
		printf("Second SetNamedSecurityInfo call failed: %u\n",
			dwRes);
	}

Cleanup:

	if (pSIDAdmin)
		FreeSid(pSIDAdmin);

	if (pSIDEveryone)
		FreeSid(pSIDEveryone);

	if (pSIDLocal)
		FreeSid(pSIDLocal);

	if (pSIDLocal2)
		FreeSid(pSIDLocal2);

	if (pSIDLocal3)
		FreeSid(pSIDLocal3);

	if (pACL)
		LocalFree(pACL);

	if (hToken)
		CloseHandle(hToken);

	return bRetval;

}

int _tmain()
{
	HANDLE hToken;
	LPTSTR filePath = _T("C:\\Users\\BIT\\Desktop\\a.txt");
	HANDLE hFile = CreateFile(
		filePath,           // 파일 경로
		GENERIC_READ|GENERIC_WRITE,       // 액세스 권한
		0,                  // 공유 모드 (0은 다른 프로세스와 공유하지 않음)
		NULL, // 보안 속성
		CREATE_NEW,      // 파일이 존재해야 열림
		FILE_ATTRIBUTE_NORMAL, // 파일 속성
		NULL                // 템플릿 핸들 (사용하지 않음)
	);
	/*if (DeleteFile(_T("C:/Users/BIT/Desktop/f.txt")) == FALSE)
		printf("DeleteFile Failed : %d \n", GetLastError());
	else
		printf("DeleteFile Succeeded \n");*/

	// 해당 파일에 대한 권한을 얻음
	TakeOwnership(filePath);

	//if (DeleteFile(_T("C:/Users/BIT/Desktop/f.txt")) == FALSE)
	//	printf("DeleteFile Failed : %d \n", GetLastError());
	//else
	//	printf("DeleteFile Succeeded \n");

	_getch();

	return 0;
}
