//��ó: https://ezbeat.tistory.com/388 [Library of Ezbeat:Ƽ���丮

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
	//���ð����ĺ��ڸ� �˻��Ͽ� ������ ���� �̸��� ���÷� ��Ÿ���� �Լ�
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

//������ �������ִ� �Լ�
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
	//����� SID ����
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
	// ����� DACL�� �����Ѵ�. 
	// Everyone �׷��� ���� SID�� �����Ѵ�.
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

	// BUILIN/Administrators �׷��� ���� SID�� �����Ѵ�.
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
	// BIT ������ ���� SID�� �����Ѵ�.
	//SID ���� ��ȣ�� �ִ� �� 
	// --> ���� ��Ʈ�� DB�� ����Ǿ� �ִ� SID�� ������ ���� 
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
	// ��� ���
	_tprintf(_T("Subauthority at index %lu: %lu\n"), subAuthorityIndex, subAuthorityValue);
	//������ ������ 0���� ä����
	ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

	// Everyone�� read access�� ���Ѵ�.
	ea[0].grfAccessPermissions = GENERIC_READ|GENERIC_EXECUTE;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pSIDEveryone; // ���� ������ 0�� �ε����� everyone�� ���ٰ� �˷���

	// Administrators�� full control�� ���Ѵ�.
	ea[1].grfAccessPermissions = GENERIC_ALL;
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[1].Trustee.ptstrName = (LPTSTR)pSIDAdmin;


	//Local �ּ��� ���Ѵ�.
	//�մܿ� 
	ea[2].grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
	ea[2].grfAccessMode = GRANT_ACCESS;
	ea[2].grfInheritance = NO_INHERITANCE;
	ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[2].Trustee.ptstrName = (LPTSTR)pSIDLocal;
	//Local �ּ��� ���Ѵ�.
	ea[3].grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
	ea[3].grfAccessMode = GRANT_ACCESS;
	ea[3].grfInheritance = NO_INHERITANCE;
	ea[3].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[3].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[3].Trustee.ptstrName = (LPTSTR)pSIDLocal2;
	//Local �ּ��� ���Ѵ�.
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

	// ������Ʈ�� DACL ������ �õ��Ѵ�.
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
		// ���̻� �۾��� �ʿ� ����
		goto Cleanup;
	}
	if (dwRes != ERROR_ACCESS_DENIED)
	{
		printf("First SetNamedSecurityInfo call failed: %u\n",
			dwRes);
		goto Cleanup;
	}


	// ���� �� ȣ���� ���� �ߴٸ� ������ �źεǾ��� �����̴�.
	// SE_TAKE_OWNERSHIP_NAME ������ Ȱ��ȭ�Ѵ�. �׸��� ������Ʈ�� DACL�� �ٽ� �� �Ѵ�.

	// ȣ���� ���μ����� access token �ڵ��� ����.
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES,
		&hToken))
	{
		printf("OpenProcessToken failed: %u\n", GetLastError());
		goto Cleanup;
	}

	// SE_TAKE_OWNERSHIP_NAME Ư���� Ȱ��ȭ ��Ų��.
	if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE))
	{
		printf("You must be logged on as Administrator.\n");
		goto Cleanup;
	}

	// ������Ʈ�� security descriptor�� �ִ� onwer�� ���Ѵ�.
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

	// SE_TAKE_OWNERSHIP_NAME Ư���� ��Ȱ��ȭ ��Ų��.
	if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, FALSE))
	{
		printf("Failed SetPrivilege call unexpectedly.\n");
		goto Cleanup;
	}

	// ������Ʈ�� DACL ������ �ٽ� �õ��Ѵ�.
	// ������ ���� ������ ���Ͽ� ���� onwer�̴�.
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
		filePath,           // ���� ���
		GENERIC_READ|GENERIC_WRITE,       // �׼��� ����
		0,                  // ���� ��� (0�� �ٸ� ���μ����� �������� ����)
		NULL, // ���� �Ӽ�
		CREATE_NEW,      // ������ �����ؾ� ����
		FILE_ATTRIBUTE_NORMAL, // ���� �Ӽ�
		NULL                // ���ø� �ڵ� (������� ����)
	);
	/*if (DeleteFile(_T("C:/Users/BIT/Desktop/f.txt")) == FALSE)
		printf("DeleteFile Failed : %d \n", GetLastError());
	else
		printf("DeleteFile Succeeded \n");*/

	// �ش� ���Ͽ� ���� ������ ����
	TakeOwnership(filePath);

	//if (DeleteFile(_T("C:/Users/BIT/Desktop/f.txt")) == FALSE)
	//	printf("DeleteFile Failed : %d \n", GetLastError());
	//else
	//	printf("DeleteFile Succeeded \n");

	_getch();

	return 0;
}
