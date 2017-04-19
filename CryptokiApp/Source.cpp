#include<iostream>
#include<Windows.h>
#include"cryptoki.h"

typedef int(*C_Initialize_decl)(void *);
typedef int(*C_GetSlotList_decl)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
typedef int(*C_GetSlotInfo_decl)(CK_SLOT_ID,CK_SLOT_INFO_PTR);
typedef int(*C_GetTokenInfo_decl)(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
using namespace std;


HINSTANCE loadpkcslib()
{
	HINSTANCE hLib = LoadLibrary(L"eTPKCS11.dll");

	if (hLib == NULL)
	{
		printf("Error loading PKCS#11 library!");
	}
	else
	{
		printf("PKCS#11 library succesfully loaded!");
	}
	return hLib;
}

void *LoadProc(HINSTANCE hLib, const char* func)
{
	void *ldfunc = (void*)GetProcAddress(hLib, func);

	if (!ldfunc)
	{
		printf("Error loading function %s() \n", func);
		abort();
	}

	return ldfunc;
}


int main()
{
	HINSTANCE hLib;
	int ret;

	hLib = loadpkcslib();

	C_Initialize_decl		C_Initialize = (C_Initialize_decl)LoadProc(hLib, "C_Initialize");
	C_GetSlotList_decl		C_GetSlotList = (C_GetSlotList_decl)LoadProc(hLib, "C_GetSlotList");
	C_GetSlotInfo_decl		C_GetSlotInfo = (C_GetSlotInfo_decl)LoadProc(hLib, "C_GetSlotInfo");
	C_GetTokenInfo_decl		C_GetTokenInfo = (C_GetTokenInfo_decl)LoadProc(hLib, "C_GetTokenInfo");

	if (ret=C_Initialize(NULL_PTR) != CKR_OK)
	{
		printf("FAIL!!!  %d",ret);
	}


	CK_ULONG ulCount;
	CK_SLOT_ID_PTR pSlotList;
	CK_SLOT_INFO slotInfo;
	CK_TOKEN_INFO tokenInfo;
	CK_RV rv;

	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &ulCount);
	if ((rv == CKR_OK) && (ulCount > 0))
	{
		pSlotList = (CK_SLOT_ID_PTR)malloc(ulCount * sizeof(CK_SLOT_ID));
		rv = C_GetSlotList(CK_FALSE, pSlotList, &ulCount);
		/* Get slot information for first slot */
		rv = C_GetSlotInfo(pSlotList[0], &slotInfo);

		/* Get token information for first slot */
		rv = C_GetTokenInfo(pSlotList[0], &tokenInfo);
		
		cout << "Informatii despre token...\n";
		cout << "\n\n";

		cout <<tokenInfo.firmwareVersion.major << "." << tokenInfo.firmwareVersion.minor << endl;
		cout << tokenInfo.flags << endl;
		cout << tokenInfo.hardwareVersion.major << "." << tokenInfo.hardwareVersion.minor << endl;
		cout << tokenInfo.label << endl;
		cout << tokenInfo.manufacturerID << endl;
		cout << tokenInfo.model << endl;
		cout << tokenInfo.serialNumber << endl;
		cout << tokenInfo.ulFreePrivateMemory << endl;
		cout << tokenInfo.ulFreePublicMemory << endl;
		cout << tokenInfo.ulMaxPinLen << endl;
		cout << tokenInfo.ulMaxRwSessionCount << endl; 
		cout << tokenInfo.ulMaxSessionCount << endl;
		cout << tokenInfo.ulMinPinLen << endl;
		cout << tokenInfo.ulRwSessionCount << endl;
		cout << tokenInfo.ulSessionCount << endl;
		cout << tokenInfo.ulTotalPrivateMemory << endl;
		cout << tokenInfo.ulTotalPublicMemory << endl;
		cout << tokenInfo.utcTime << endl;




	}
	
}
