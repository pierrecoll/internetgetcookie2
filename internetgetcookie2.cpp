// internetgetcookie.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//
#include "stdio.h"
#include <Windows.h>
#include <WinInet.h>
#include <iepmapi.h>
#include <sddl.h>
#include "time.h"

#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"urlmon.lib")
#pragma comment(lib,"iepmapi.lib")

DWORD GetProcessIntegrityLevel();
DWORD ErrorPrint();
void CreateLowProcess();
WCHAR* ExtractSingleCookieToken(LPTSTR lpszData);
void FindCookies(WCHAR* wszUrl);
void FindCookie(WCHAR* wszUrl, WCHAR* wszCookieName);
BOOL CreateCookie(WCHAR* wszUrl, WCHAR* wszCookieName, WCHAR* wszCookieValue);
BOOL DeleteCookie(INTERNET_COOKIE2* pInternetCookie);
void DumpCookie(INTERNET_COOKIE2* pInternetCookie);
void ShowUsage();
BOOL SetUrl(char* Url);
void  SetCookie(char* CookieName);
void  SetCookieValue(char* CookieValue);
FILETIME ComputeFromCurrentTime(INT32 days, INT32 hours, INT32 minutes, INT32 seconds);

BOOL bProtectedModeUrl = FALSE;
DWORD dwProcessIntegrityLevel = 0;
WCHAR wszUrl[INTERNET_MAX_URL_LENGTH] = L"";
WCHAR wszCookieName[INTERNET_MAX_URL_LENGTH] = L"";
WCHAR wszCookieValue[INTERNET_MAX_URL_LENGTH] = L"";
BOOL bDeleteCookie = FALSE;
BOOL bCreateCookie = FALSE;
BOOL bVerbose = FALSE;


void ShowUsage()
{
	wprintf(L"INTERNETGETCOOKIE2 version 1.2\r\n");
	wprintf(L"\r\n");
	wprintf(L"pierrelc@microsoft.com April 2021\r\n");
	wprintf(L"Usage: INTERNETGETCOOKIE2 accepts an URL as parameter and optionally a cookie name.\r\n");
	wprintf(L"internetgetcookie2 [-c[v]|[-d[v]|-v|-?|-h] url [cookiename][cookievalue]\r\n");
	wprintf(L"-d (or -dv for verbose mode) to delete the cookie if it is found\r\n");
	wprintf(L"-c (or -cv for verbose mode) to create a cookie\r\n");
	wprintf(L"-v for verbose mode)\r\n");
	wprintf(L"Uses InternetGetCookieEx2 API  https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetgetcookieex2\r\n");
}

int main(int argc, char* argv[])
{
	BOOL bReturn = FALSE;
	BOOL bSearchCookie = FALSE;

	if ((argc != 2) && (argc != 3) && (argc != 4) && (argc != 5) || (argc==1))
	{
		ShowUsage();
		exit(0L);
	}
	char arg[MAX_PATH];

	strcpy_s(arg, argv[1]);
	//_strupr_s(arg);
	char* Parameter = strstr(arg, "-");

	//First argument does not start with -
	if (!Parameter)
	{
		if (argc >= 2)
		{
			bReturn = SetUrl(argv[1]);
			if (bReturn == FALSE)
				exit(-1L);
		}
		if (argc ==3)
		{
			bSearchCookie = TRUE;
			SetCookie(argv[2]);
			goto ParamParsed;
		}
	}
	else
	{
		//Help
		if ((!strcmp(arg, "-h")) || (!strcmp(arg, "-?")))
		{
			ShowUsage();
			exit(0L);
		}

		//Delete
		else if ((!strcmp(arg, "-d")) || (!strcmp(arg, "-dv")))
		{
			if (argc != 4)
			{
				wprintf(L"-d option requires a cookie name as third parameter\r\n");
				ShowUsage();
				exit(0L);
			}
			if (!strcmp(arg, "-dv"))
			{
				bVerbose = TRUE;
				if (bVerbose) wprintf(L"Verbose mode on\r\n");
			}
			bDeleteCookie = TRUE;
			if (bVerbose) wprintf(L"Option to delete cookie set\r\n");
			bReturn = SetUrl(argv[2]);
			if (bReturn == FALSE)
				exit(-1L);
			else
			{
				bSearchCookie = TRUE;
				SetCookie(argv[3]);
				goto ParamParsed;
			}
		}
		//Create
		else if ((!strcmp(arg, "-c")) || (!strcmp(arg, "-cv")))
		{
			if (argc != 5)
			{
				wprintf(L"-c option requires a cookie name as third parameter and cookie value as fourth parameter\r\n");
				ShowUsage();
				exit(0L);
			}
			if (!strcmp(arg, "-cv"))
			{
				bVerbose = TRUE;
				if (bVerbose) wprintf(L"Verbose mode on\r\n");
			}
			bCreateCookie = TRUE;
			if (bVerbose) wprintf(L"Option to create cookie set\r\n");
			bReturn = SetUrl(argv[2]);
			if (bReturn == FALSE)
				exit(-1L);
			else
			{
				SetCookie(argv[3]);
				SetCookieValue(argv[4]);
				goto ParamParsed;
			}
		}
		else if (!strcmp(arg, "-v")) 
		{
			bVerbose = TRUE;
			if (bVerbose) wprintf(L"Verbose mode on\r\n");
			bReturn = SetUrl(argv[2]);
			if (bReturn == FALSE)
			{
				exit(-1L);
			}
			if (argc==4)
			{
				bSearchCookie = TRUE;
				SetCookie(argv[3]);
				goto ParamParsed;
			}
		}
		else
		{
			ShowUsage();
			exit(0L);
		}
	}

ParamParsed:

	dwProcessIntegrityLevel = GetProcessIntegrityLevel();

	if (bVerbose) wprintf(L"Calling IEIsProtectedModeURL for url : %s\r\n", wszUrl);
	HRESULT hr = IEIsProtectedModeURL(wszUrl);
	if (hr == S_OK)
	{
		bProtectedModeUrl = TRUE;
		if (bVerbose) wprintf(L"Url would open in a protected mode process.\r\n");
	}
	else if (hr == S_FALSE)
	{
		if (bVerbose) wprintf(L"Url would not open in a protected mode process.\r\n");
	}
	else
	{
		if (bVerbose) wprintf(L"IEIsProtectedModeURL returning : %X\r\n", hr);
	}
	 
	if (bCreateCookie == TRUE)
	{
			BOOL bReturn=CreateCookie(wszUrl,wszCookieName,wszCookieValue);
			if (bReturn == TRUE)
			{
				FindCookie(wszUrl, wszCookieName);
			}
			return 0L;
	}
	if (bSearchCookie==FALSE)
	{
		FindCookies(wszUrl);
	}
	else
	{
		FindCookie(wszUrl, wszCookieName);
	}

	return 0L;
}

void  SetCookie(char* CookieName)
{
	MultiByteToWideChar(CP_ACP, 0, CookieName, strlen(CookieName), wszCookieName, INTERNET_MAX_URL_LENGTH);
	CookieName[strlen(CookieName)] = 0;
	wprintf(L"Cookie Name : %s\r\n", wszCookieName);
}

void  SetCookieValue(char* CookieValue)
{
	MultiByteToWideChar(CP_ACP, 0, CookieValue, strlen(CookieValue), wszCookieValue, INTERNET_MAX_URL_LENGTH);
	CookieValue[strlen(CookieValue)] = 0;
	wprintf(L"Cookie Name : %s\r\n", wszCookieName);
}

BOOL SetUrl(char* Url)
{
	MultiByteToWideChar(CP_ACP, 0, Url, strlen(Url), wszUrl, INTERNET_MAX_URL_LENGTH);
	wszUrl[strlen(Url)] = 0;
	wprintf(L"Url : %s\r\n", wszUrl);

	//checking protocol of the url.Must be http or https
	int ch = ':';
	char* pdest;
	char protocol[6] = "";
	int result;

	// Search forward.
	pdest = strchr(Url, ch);
	result = (int)(pdest - Url + 1);
	if (pdest != NULL)
	{
		if (result > 6)
		{
			wprintf(L"The protocol for the url must be http or https\r\n");
			return(FALSE);
		}
		lstrcpynA(protocol, Url, result);
		protocol[result - 1] = '\0';
		if (bVerbose) wprintf(L"Protocol of the url is: %S\r\n", protocol);
		if ((strncmp(protocol, "http", result - 1) != 0) && (strncmp(protocol, "https", result - 1) != 0))
		{
			wprintf(L"The protocol for the url must be http or https\r\n");
			return(FALSE);
		}
	}
	else
	{
		wprintf(L"The protocol for the url must be http or https\r\n");
		return(FALSE);
	}
	return(TRUE);
}
void DumpCookie(INTERNET_COOKIE2* pInternetCookie)
{
	
	if (pInternetCookie != 0)
	{
		wprintf(L"Cookie name : %s\r\n", pInternetCookie->pwszName);
		wprintf(L"\tCookie value : %s\r\n", pInternetCookie->pwszValue);
		wprintf(L"\tCookie domain:  %s\r\n", pInternetCookie->pwszDomain);
		wprintf(L"\tCookie path : %s\r\n", pInternetCookie->pwszPath);
		wprintf(L"\tCookie flags : %X\r\n", pInternetCookie->dwFlags);

		if (pInternetCookie->dwFlags & INTERNET_COOKIE_IS_SECURE)
		{
			wprintf(L"\t\tThis is a secure cookie.\r\n");
		}		
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_IS_SESSION)
		{
			wprintf(L"\t\tThis is a session cookie.r\n");
		}		
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_IS_RESTRICTED)
		{
			wprintf(L"\t\tThis cookie is restricted to first - party contexts.\r\n");
		}		
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_HTTPONLY)
		{
			wprintf(L"\t\tThis is an HTTP - only cookie.\r\n");
		}		
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_HOST_ONLY )
		{
			wprintf(L"\t\tThis is a host - only cookie.\r\n");
		}		
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_HOST_ONLY_APPLIED)
		{
			wprintf(L"\t\tThe host - only setting has been applied to this cookie.\r\n");
		}		
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_SAME_SITE_STRICT)
		{
			wprintf(L"\t\tThe SameSite security level for this cookie is \"strict\"\r\n");
		}
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_SAME_SITE_LAX)
		{
			wprintf(L"\t\tThe SameSite security level for this cookie is \"lax\"\r\n");
		}
								
		wprintf(L"\tExpiry time set : %S\r\n", pInternetCookie->fExpiresSet ? "true" : "false");

		TIME_ZONE_INFORMATION tzi;
		GetTimeZoneInformation(&tzi);

		SYSTEMTIME st, stLocal;
		BOOL bRV = FileTimeToSystemTime(&pInternetCookie->ftExpires, &st);
		SystemTimeToTzSpecificLocalTime(&tzi, &st, &stLocal);
		WCHAR szBuf[256];
		GetDateFormat(LOCALE_USER_DEFAULT, DATE_LONGDATE, &stLocal, NULL, szBuf, sizeof(szBuf));

		int iBufUsed = wcslen(szBuf);
		if (iBufUsed < sizeof(szBuf) - 2)
			szBuf[iBufUsed++] = ' ';
		GetTimeFormat(LOCALE_USER_DEFAULT, 0, &stLocal,
			NULL, szBuf + iBufUsed, sizeof(szBuf) - iBufUsed);
		char OEMTime[256];
		CharToOemBuff(szBuf, (LPSTR)OEMTime, wcslen(szBuf));
		OEMTime[wcslen(szBuf)] = '\0';

		wprintf(L"\tExpiry time : %S\r\n", OEMTime);
		wprintf(L"\r\n");
	}
}


BOOL CreateCookie(WCHAR* wszUrl, WCHAR* wszCookieName, WCHAR* wszCookieValue)
{
	DWORD dwReturn = 0;

	LPTSTR lpszCookieData = NULL;   // buffer to hold the cookie data
	//DWORD dwFlags = INTERNET_COOKIE_NON_SCRIPT;
	DWORD dwFlags =  INTERNET_COOKIE_PROMPT_REQUIRED;
	DWORD dwCookieCount = 0;
	INTERNET_COOKIE2 InternetCookie = {0};
	DWORD dwCookieState;

	InternetCookie.pwszName = wszCookieName;
	InternetCookie.pwszValue = wszCookieValue;
	InternetCookie.pwszPath=(PWSTR)  L"/";
	InternetCookie.fExpiresSet = true;


	FILETIME ft = {};
	GetSystemTimeAsFileTime(&InternetCookie.ftExpires);
	//setting epiry to current time plus one day
	InternetCookie.ftExpires = ComputeFromCurrentTime(+1, 0, 0, 0);
	if (bVerbose) wprintf(L"Calling InternetSetCookieEx2 for url %s and cookie name %s and cookie value %s dwFlags: %X\r\n", wszUrl, wszCookieName, wszCookieValue, dwFlags);
	dwReturn = InternetSetCookieEx2(wszUrl, &InternetCookie, NULL, dwFlags, &dwCookieState);
	if (bVerbose) wprintf(L"InternetSetCookieEx2 returning %d\r\n", dwReturn);
	if (dwReturn != ERROR_SUCCESS) 
	{	
		if (dwProcessIntegrityLevel == SECURITY_MANDATORY_HIGH_RID)
		{
			wprintf(L"Starting low cannot be done from an administrative command prompt (High Integrity Level)\r\n");
			exit(-1L);
		}
		else if (dwProcessIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
		{
			//¨process already Low 
			wprintf(L"Process already running at low integrity\r\n");
			wprintf(L"Cookie %s not found for url:%s\r\n", wszCookieName, wszUrl);
			wprintf(L"Type enter to exit low integrity level!\r\n");
			exit(-2L);
		}
		else if (dwProcessIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID)
		{
			wprintf(L"Trying to start as low integrity level process\r\n");
			CreateLowProcess();
			exit(0L);
		}
		else
		{
			wprintf(L"Unexpected integity level for -low option\r\n");
		}
	}
	else
	{
		if (bVerbose) wprintf(L"InternetSetCookieEx2 succeeded\r\n");
		if (dwReturn == ERROR_SUCCESS)
		{
			switch (dwCookieState)
			{
			case COOKIE_STATE_UNKNOWN:
				wprintf(L"Cookie state Reserved.");
				break;
			case COOKIE_STATE_ACCEPT:
				wprintf(L"The cookie(s) state change has been accepted.\r\n");
				break;
			case COOKIE_STATE_PROMPT:
				wprintf(L"The user is prompted to accept or deny the cookie\r\n");
				break;
			case COOKIE_STATE_LEASH:
				wprintf(L"Cookies are accepted only in the first - party context.\r\n");
				break;
			case COOKIE_STATE_DOWNGRADE:
				wprintf(L"Cookies are accepted and become session cookies.\r\n");
				break;
			case COOKIE_STATE_REJECT:
				wprintf(L"The cookies are rejected.\r\n");
				break;
			default:
				wprintf(L"Unknown cookie state.\r\n");
				break;
			}
		}
		DumpCookie(&InternetCookie);

	}
	return TRUE;
}

void FindCookie(WCHAR* wszUrl, WCHAR* wszCookieName)
{
	DWORD dwReturn = 0;

	LPTSTR lpszCookieData = NULL;   // buffer to hold the cookie data
	DWORD dwFlags = INTERNET_COOKIE_NON_SCRIPT;
	DWORD dwCookieCount = 0;
	INTERNET_COOKIE2* pInternetCookie;

	if (bVerbose) wprintf(L"Calling InternetGetCookieEx2 for url %s and cookie name %s dwFlags: %X\r\n", wszUrl, wszCookieName, dwFlags);
	dwReturn = InternetGetCookieEx2(wszUrl, wszCookieName, dwFlags, &pInternetCookie, &dwCookieCount);
	if (bVerbose) wprintf(L"InternetGetCookieEx2 returning %d Cookie Count : %d\r\n", dwReturn, dwCookieCount);
	if ((dwReturn != ERROR_SUCCESS) || (dwCookieCount == 0))
	{
		if (dwProcessIntegrityLevel == SECURITY_MANDATORY_HIGH_RID)
		{
			wprintf(L"Starting low cannot be done from an administrative command prompt (High Integrity Level)\r\n");
			exit(-1L);
		}
		else if (dwProcessIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
		{
			//¨process already Low 
			wprintf(L"Process already running at low integrity\r\n");
			wprintf(L"Cookie %s not found for url:%s\r\n", wszCookieName, wszUrl);
			wprintf(L"Type enter to exit low integrity level!\r\n");
			exit(-2L);
		}
		else if (dwProcessIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID)
		{
			wprintf(L"Trying to start as low integrity level process\r\n");
			CreateLowProcess();
			exit(0L);
		}
		else
		{
			wprintf(L"Unexpected integity level for -low option\r\n");
		}
	}
	else 
	{
		if (bVerbose) wprintf(L"InternetGetCookieEx2 succeeded. dwCookieCount = %d\r\n", dwCookieCount);
		DumpCookie(pInternetCookie);
		if (bDeleteCookie == TRUE)
		{
			if (bVerbose) wprintf(L"Deleting cookie\r\n");
			DeleteCookie(pInternetCookie);
		}
		InternetFreeCookies(pInternetCookie, dwCookieCount);
	}
}

void FindCookies(WCHAR* wszUrl)
{
	DWORD dwReturn = 0;

	LPTSTR lpszCookieData = NULL;   // buffer to hold the cookie data
	DWORD dwFlags = INTERNET_COOKIE_NON_SCRIPT;
	DWORD dwCookieCount = 0;
	INTERNET_COOKIE2* pInternetCookie;

	if (bVerbose) wprintf(L"Calling InternetGetCookieEx2 for url %s and no cookie name . dwFlags: %X\r\n", wszUrl, dwFlags);
	dwReturn = InternetGetCookieEx2(wszUrl, NULL, dwFlags, &pInternetCookie, &dwCookieCount);
	if (bVerbose) wprintf(L"InternetGetCookieEx2 returning %d Cookie Count : %d\r\n", dwReturn, dwCookieCount);
	if ((dwReturn != ERROR_SUCCESS) || (dwCookieCount == 0))
	{
		if (bVerbose) wprintf(L"dwReturn: %d dwCookiecount: %d\r\n", dwReturn, dwCookieCount);
		if (dwProcessIntegrityLevel == SECURITY_MANDATORY_HIGH_RID)
		{
			wprintf(L"Starting low cannot be done from an administrative command prompt (High Integrity Level)\r\n");
			exit(-1L);
		}
		else if (dwProcessIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
		{
			//¨process already Low 
			wprintf(L"Process already running at low integrity\r\n");
			wprintf(L"Cookie %s not found for url:%s\r\n", wszCookieName, wszUrl);
			wprintf(L"Type enter to exit low integrity level\r\n");
			exit(-2L);
		}
		else if (dwProcessIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID)
		{
			wprintf(L"Trying to start as low integrity process\r\n");
			CreateLowProcess();
			exit(0L);
		}
		else
		{
			wprintf(L"Unexpected integity level for -low option\r\n");
		}
	}
	else
	{
		if (bVerbose) wprintf(L"InternetGetCookieEx2 succeeded. dwCookieCount = %d\r\n", dwCookieCount);
		unsigned int i = 0;
		for (i = 0; i < dwCookieCount; i++)
		{
			DumpCookie(&pInternetCookie[i]);
		}		
		InternetFreeCookies(pInternetCookie, dwCookieCount);
	}
}



BOOL DeleteCookie(INTERNET_COOKIE2* pInternetCookie)
{
	DWORD dwReturn = 0;

	LPTSTR lpszCookieData = NULL;   // buffer to hold the cookie data
	DWORD dwFlags = INTERNET_COOKIE_NON_SCRIPT;
	DWORD dwCookieState = 0;

	pInternetCookie->fExpiresSet = TRUE;
	pInternetCookie->ftExpires = ComputeFromCurrentTime(-1, 0, 0, 0);
	if (bVerbose) wprintf(L"Setting expiry time to current time minus one day\r\n");
	if (bVerbose) wprintf(L"Calling InternetSetCookieEx2 for url %s and cookie name %s dwFlags: %X fExpiresSet:%d \r\n", wszUrl, wszCookieName, dwFlags, pInternetCookie->fExpiresSet);
	dwReturn = InternetSetCookieEx2(wszUrl,pInternetCookie, NULL, dwFlags,  &dwCookieState);
	if (bVerbose) wprintf(L"InternetGetCookieEx2 returning %d Cookie Count : %d\r\n", dwReturn, dwCookieState);

	if (dwReturn == ERROR_SUCCESS) 
	{
		switch (dwCookieState)
		{
		case COOKIE_STATE_UNKNOWN:
			wprintf(L"Cookie state Reserved.");
			break;
		case COOKIE_STATE_ACCEPT:
			wprintf(L"The cookie(s) state change has been accepted.\r\n");
			break;
		case COOKIE_STATE_PROMPT:
			wprintf(L"The user is prompted to accept or deny the cookie\r\n");
				break;
		case COOKIE_STATE_LEASH:
			wprintf(L"Cookies are accepted only in the first - party context.\r\n");
				break;
		case COOKIE_STATE_DOWNGRADE:
			wprintf(L"Cookies are accepted and become session cookies.\r\n");
				break;
		case COOKIE_STATE_REJECT:
			wprintf(L"The cookies are rejected.\r\n");
				break;
		default:
			wprintf(L"Unknown cookie state.\r\n");
			break;
		}
		DumpCookie(pInternetCookie);
		return TRUE;
	}
	
	if (bProtectedModeUrl)
	{
		HRESULT hr = S_FALSE;
		if (bVerbose) wprintf(L"Deleting cookie %s by calling IESetProtectedModeCookie with expiration date set to Sat,01-Jan-2000 00:00:00 GMT\r\n", wszCookieName);
		hr = IESetProtectedModeCookie(wszUrl, wszCookieName, TEXT("Deleted;expires=Sat,01-Jan-2000 00:00:00 GMT"), 0L);
		if (FAILED(hr))
		{
			if (bVerbose) wprintf(L"IESetProtectedModeCookie failed with error : %X\r\n", hr);
			if (bVerbose) wprintf(L"Calling IESetProtectedModeCookie with flag INTERNET_COOKIE_NON_SCRIPT\r\n");
			hr = IESetProtectedModeCookie(wszUrl, wszCookieName,
				TEXT("Deleted;expires=Sat,01-Jan-2000 00:00:00 GMT"), INTERNET_COOKIE_NON_SCRIPT);
			if (FAILED(hr))
			{
				if (bVerbose) wprintf(L"IESetProtectedModeCookie failed with error : %X.\r\n", hr);
				return FALSE;
			}
			else
			{
				if (bVerbose) wprintf(L"Calling IESetProtectedModeCookie to delete cookie %s succeeded.\r\n", wszCookieName);
				return TRUE;
			}
		}
		else
		{
			if (bVerbose) wprintf(L"Calling IESetProtectedModeCookie to delete cookie %s succeeded.\r\n", wszCookieName);
			return TRUE;
		}
	}
	return FALSE;
}

//From https://msdn.microsoft.com/en-us/library/bb250462(VS.85).aspx(d=robot)
void CreateLowProcess()
{
	BOOL bRet;
	HANDLE hToken;
	HANDLE hNewToken;

	// Notepad is used as an example
	WCHAR wszProcessName[MAX_PATH];
	GetModuleFileNameW(NULL, wszProcessName, MAX_PATH - 1);
	WCHAR* lpwszCommandLine = GetCommandLineW();

	// Low integrity SID
	WCHAR wszIntegritySid[20] = L"S-1-16-4096";
	//WCHAR wszIntegritySid[129] = L"S-1-15-2-3624051433-2125758914-1423191267-1740899205-1073925389-3782572162-737981194-4256926629-1688279915-2739229046-3928706915";
	PSID pIntegritySid = NULL;

	TOKEN_MANDATORY_LABEL TIL = { 0 };
	PROCESS_INFORMATION ProcInfo = { 0 };
	STARTUPINFOW StartupInfo = { 0 };
	ULONG ExitCode = 0;

	if (OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken))
	{
		if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
			SecurityImpersonation, TokenPrimary, &hNewToken))
		{
			if (ConvertStringSidToSidW(wszIntegritySid, &pIntegritySid))
			{
				TIL.Label.Attributes = SE_GROUP_INTEGRITY;
				TIL.Label.Sid = pIntegritySid;

				// Set the process integrity level
				if (SetTokenInformation(hNewToken, TokenIntegrityLevel, &TIL,
					sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid)))
				{
					// Create the new process at Low integrity
					bRet = CreateProcessAsUserW(hNewToken, wszProcessName,
						lpwszCommandLine, NULL, NULL, FALSE,
						0, NULL, NULL, &StartupInfo, &ProcInfo);
					if (!bRet)
					{
						if (bVerbose) wprintf(L"CreateProcessAsUserW failed\r\n");
						ErrorPrint();
					}
					else
					{
						if (bVerbose) wprintf(L"CreateProcessAsUser %ws with Low Integrity. Command line: %ws\r\n", wszProcessName, lpwszCommandLine);
					}
				}
				else
				{
					if (bVerbose) wprintf(L"SetTokenInformation failed\r\n");
					ErrorPrint();
				}
				LocalFree(pIntegritySid);
			}
			else
			{
				if (bVerbose) wprintf(L"ConvertStringSidToSidW failed\r\n");
				ErrorPrint();
			}
			CloseHandle(hNewToken);
		}
		else
		{
			if (bVerbose) wprintf(L"DuplicateTokenEx failed\r\n");
			ErrorPrint();
		}
		CloseHandle(hToken);
	}
	else
	{
		if (bVerbose) wprintf(L"OpenProcessToken failed\r\n");
		ErrorPrint();
	}
}
DWORD GetProcessIntegrityLevel()
{
	HANDLE hToken;
	HANDLE hProcess;

	DWORD dwLengthNeeded;
	DWORD dwError = ERROR_SUCCESS;

	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	DWORD dwIntegrityLevel;

	hProcess = GetCurrentProcess();
	if (OpenProcessToken(hProcess, TOKEN_QUERY |
		TOKEN_QUERY_SOURCE, &hToken))
	{
		// Get the Integrity level.
		if (!GetTokenInformation(hToken, TokenIntegrityLevel,
			NULL, 0, &dwLengthNeeded))
		{
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0,
					dwLengthNeeded);
				if (pTIL != NULL)
				{
					if (GetTokenInformation(hToken, TokenIntegrityLevel,
						pTIL, dwLengthNeeded, &dwLengthNeeded))
					{
						dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
							(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

						if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
						{
							// Low Integrity
							if (bVerbose) wprintf(L"Running at Low Integrity Level\r\n");
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
							dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
						{
							// Medium Integrity
							if (bVerbose) wprintf(L"Running at Medium Integrity Level\r\n");
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
						{
							// High Integrity
							if (bVerbose) wprintf(L"Running at High Integrity Level\r\n");
						}
						return dwIntegrityLevel;
					}
					else
					{
						if (bVerbose) wprintf(L"GetProcessIntegrityLevel: GetTokenInformation failed\r\n");
						ErrorPrint();
					}
					LocalFree(pTIL);
				}
			}
		}
		CloseHandle(hToken);
	}
	else
	{
		if (bVerbose) wprintf(L"GetProcessIntegrityLevel: OpenProcessToken failed\r\n");
		ErrorPrint();
	}
	return -1;
}


WCHAR* ExtractSingleCookieToken(LPTSTR lpszData)
{
	// Code to display the cookie data.
	//+		lpszData	0x010dee48 L"WebLanguagePreference=fr-fr; WT_NVR=0=/:1=web; SRCHUID=V=2&GUID=9087E76D5D4343F5BFE07F75D80435E4&dmnchg=1; SRCHD=AF=NOFORM; WT_FPC=id=2186e6812f80d94b48a1502956146257:lv=1502956146257:ss=1502956146257...	wchar_t *
	// Searching token separated by ";"

	WCHAR seps[] = L";";
	WCHAR* token = NULL;
	WCHAR* next_token = NULL;
	WCHAR* CookieName = NULL;

	//get the first token:
	token = wcstok_s(lpszData, seps, &next_token);

	// While there are token
	while (token != NULL)
	{
		// Get next token:
		if (token != NULL)
		{
			//if (bVerbose) wprintf(L" %s\n", token);
			unsigned int CookieLen = wcslen(token);
			unsigned int i;
			for (i = 0; i < CookieLen; i++)
			{
				if (*(token + i) == L'=')
				{
					*(token + i) = '\0';
					CookieName = token;
					//strip initial space if needed
					if (CookieName[0] == ' ')
					{
						CookieName += 1;
					}
					WCHAR* CookieValue = token + i + 1;
					if (bVerbose) wprintf(L"Cookie Name  = %s\r\n", CookieName);
					if (bVerbose) wprintf(L"\tValue = %s\r\n", CookieValue);
					break;
				}
			}
			token = wcstok_s(NULL, seps, &next_token);
		}
	}
	return CookieName;
}

FILETIME ComputeFromCurrentTime(INT32 days, INT32 hours, INT32 minutes, INT32 seconds)
{
#define _SECOND ((INT64) 10000000)
#define _MINUTE (60 * _SECOND)
#define _HOUR   (60 * _MINUTE)
#define _DAY    (24 * _HOUR)

	//Determining Current Time
	FILETIME fileTime;
	GetSystemTimeAsFileTime(&fileTime);

	//Converting to QuadWord for performing arithmetic
	ULONGLONG qwResult;
	qwResult = (((ULONGLONG)fileTime.dwHighDateTime) << 32) + fileTime.dwLowDateTime;

	//Add time
	qwResult += days * _DAY;
	qwResult += hours * _HOUR;
	qwResult += minutes * _MINUTE;
	qwResult += seconds * _SECOND;

	//Convert back to FILETIME
	fileTime.dwLowDateTime = (DWORD)(qwResult & 0xFFFFFFFF);
	fileTime.dwHighDateTime = (DWORD)(qwResult >> 32);

	return fileTime;
}

