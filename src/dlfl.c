#include <windows.h>
#include <winhttp.h>

#pragma comment( lib, "kernel32.lib")
#pragma comment( lib, "winhttp.lib")

#define WINHTTP_TIMEOUT 9999
#define WINHTTP_CHUNK   1280

void memzero( void * mem, size_t size ) // anti memset
{
    do
    {
        ( (volatile char *)mem )[--size] = 0;
    } while( size );
}

void memcopy( void * dst, void * src, size_t size ) // anti memcpy
{
    do
    {
        ( (volatile char *)dst )[--size] = ( (volatile char *)src )[--size];
    } while( size );
}

unsigned strlength( char * str ) // anti strlen
{
    unsigned length = 0;

    while( 0 != *str )
    {
        length++;
        str++;
    }

    return length;
}

typedef struct
{
    LPCWSTR url;
    LPCWSTR url_get;
    LPCWSTR server;
    INTERNET_PORT port;
    BOOL isSSL;

    BYTE bbChunk[WINHTTP_CHUNK];
    DWORD dwChunk;
    DWORD dwLoaded;
    DWORD dwTotal;

    HINTERNET hSession;
    HINTERNET hConnect;
    HINTERNET hRequest;
}
winhttp_handler;

#define WINHHTP_AGENT L"WinHTTP (github/deemru/dlfl)"

DWORD winhttp_exec( winhttp_handler * h )
{
    BOOL isOK = FALSE;

    if( h->hRequest )
        goto download;

    h->hSession = WinHttpOpen( WINHHTP_AGENT, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );

    if( !h->hSession )
        goto end;

    h->hConnect = WinHttpConnect( h->hSession, h->server, h->port, 0 );

    if( !h->hConnect )
        goto end;

    h->hRequest = WinHttpOpenRequest( h->hConnect, L"GET", h->url_get, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, h->isSSL ? WINHTTP_FLAG_SECURE : 0 );

    if( !h->hRequest )
        goto end;

    isOK = WinHttpSetTimeouts( h->hRequest, 0, WINHTTP_TIMEOUT, WINHTTP_TIMEOUT, WINHTTP_TIMEOUT );

    if( !isOK )
        goto end;

    // PROXY-CODE
    {
        WINHTTP_PROXY_INFO ProxyInfo;

        isOK = FALSE;
        {
            WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ProxyConfig;

            memzero( &ProxyConfig, sizeof( WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ) );
            ProxyConfig.fAutoDetect = TRUE;

            if( WinHttpGetIEProxyConfigForCurrentUser( &ProxyConfig ) )
            {
                if( ProxyConfig.lpszProxy && ProxyConfig.lpszProxy[0] )
                {
                    ProxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                    ProxyInfo.lpszProxy = ProxyConfig.lpszProxy;
                    ProxyInfo.lpszProxyBypass = ProxyConfig.lpszProxyBypass;

                    if( WinHttpSetOption( h->hRequest, WINHTTP_OPTION_PROXY, &ProxyInfo, sizeof( ProxyInfo ) ) )
                        isOK = TRUE;
                }

                if( ProxyConfig.lpszProxy )
                    GlobalFree( ProxyConfig.lpszProxy );

                if( ProxyConfig.lpszProxyBypass )
                    GlobalFree( ProxyConfig.lpszProxyBypass );

                if( ProxyConfig.lpszAutoConfigUrl )
                    GlobalFree( ProxyConfig.lpszAutoConfigUrl );
            }
            else
            {
                if( GetLastError() == ERROR_FILE_NOT_FOUND )
                    isOK = TRUE;
            }
        }

        if( !isOK )
        {
            WINHTTP_AUTOPROXY_OPTIONS AutoProxyOptions;

            memzero( &AutoProxyOptions, sizeof( WINHTTP_AUTOPROXY_OPTIONS ) );
            AutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
            AutoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
            AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

            if( WinHttpGetProxyForUrl( h->hSession, h->url, &AutoProxyOptions, &ProxyInfo ) )
            {
                if( WinHttpSetOption( h->hRequest, WINHTTP_OPTION_PROXY, &ProxyInfo, sizeof( ProxyInfo ) ) )
                    isOK = TRUE;
            }
            else
            {
                if( GetLastError() == ERROR_WINHTTP_AUTODETECTION_FAILED ||
                    GetLastError() == ERROR_NOT_FOUND )
                    isOK = TRUE;
            }

            if( ProxyInfo.lpszProxy )
                GlobalFree( ProxyInfo.lpszProxy );

            if( ProxyInfo.lpszProxyBypass )
                GlobalFree( ProxyInfo.lpszProxyBypass );
        }

        if( !isOK )
            goto end;
    }

    isOK = WinHttpSendRequest( h->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 );

    if( !isOK )
        goto end;

    isOK = WinHttpReceiveResponse( h->hRequest, NULL );

    if( !isOK )
        goto end;

    {
        DWORD dwValue, dwSize = sizeof( dwValue );
        isOK = WinHttpQueryHeaders( h->hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwValue, &dwSize, WINHTTP_NO_HEADER_INDEX );

        if( !isOK )
            goto end;

        if( dwValue != HTTP_STATUS_OK )
        {
            isOK = 0;
            SetLastError( (DWORD)NTE_NOT_FOUND );
            goto end;
        }

        isOK = WinHttpQueryHeaders( h->hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwValue, &dwSize, WINHTTP_NO_HEADER_INDEX );

        if( !isOK )
            h->dwTotal = 0;
        else
            h->dwTotal = dwValue;
    }


download:

    h->dwChunk = sizeof( h->bbChunk );
    isOK = WinHttpReadData( h->hRequest, h->bbChunk, h->dwChunk, &h->dwChunk );

    if( !isOK )
        goto end;

    h->dwLoaded += h->dwChunk;

    if( h->dwChunk )
        return S_OK;

end:

    {
        DWORD dwTemp = isOK ? S_OK : GetLastError();

        if( h->hRequest ) WinHttpCloseHandle( h->hRequest );
        if( h->hConnect ) WinHttpCloseHandle( h->hConnect );
        if( h->hSession ) WinHttpCloseHandle( h->hSession );

        return dwTemp;
    }
}

unsigned str2num( wchar_t * str )
{
    unsigned u = 0;
    wchar_t c;

    while( 0 != ( c = *str++ ) )
        u = u * 10 + c - '0';

    return u;
}

char bytesize_MB[] = "_____ MB";
char bytesize_KB[] = "_____ KB";
char bytesize_B[] = "_____ B";

char * num2bytesize( unsigned u )
{
    char * measure;
    char * str;

    if( u > 1024 * 1024 * 10 )
    {
        u /= 1024 * 1024;
        measure = bytesize_MB;
    }
    else if( u > 1024 * 10 )
    {
        u /= 1024;
        measure = bytesize_KB;
    }
    else
    {
        measure = bytesize_B;
    }

    str = measure + 5;

    do
    {
        str--;
        *str = u % 10 + '0';
        u /= 10;
    } while( u );

    return str;
}

unsigned strbreaker( wchar_t * str, wchar_t ** argv, unsigned max, wchar_t breaker, wchar_t quote )
{
    wchar_t c;
    wchar_t is_begin = 0;
    wchar_t is_quote = 0;
    unsigned argc = 0;

    while( 0 != ( c = *str ) )
    {
        if( !is_begin )
        {
            if( c == breaker )
            {
                str++;
                continue;
            }

            else
            {
                if( argc >= max )
                    return max;

                is_begin = 1;
                if( c == quote )
                {
                    is_quote = 1;
                    str++;
                }
                argv[argc] = str;
                continue;
            }
        }

        if( c == quote )
        {
            if( !is_quote )
                return 0;

            is_begin = 0;
            is_quote = 0;
            *str = 0;
            str++;
            argc++;
            continue;
        }

        if( is_quote )
        {
            str++;
            continue;
        }

        if( c == breaker )
        {
            is_begin = 0;
            *str = 0;
            str++;
            argc++;
            continue;
        }

        str++;
    }

    if( is_begin )
        argc++;

    return argc;
}

#define LOG_ERR_PROLOG  "ERROR: "
#define LOG_ERR_BAD_CMD "Bad command line"
#define LOG_ERR_WINHTTP "WinHTTP unknown error"
#define LOG_ERR_CREATEFILE "CreateFile failed"
#define LOG_ERR_WRITEFILE "WriteFile failed"
#define LOG_ERR_EPILOG  ".\r\n"

#define LOG_DOWNLOAD_PROLOG  "Downloading"
#define LOG_DOWNLOAD_SIZE_PROLOG " "
#define LOG_DOWNLOAD_EPILOG  ": .."
#define LOG_DOWNLOADING  "."
#define LOG_SUCCESS  " OK.\r\n"

void strlogger( HANDLE hOut, char * prolog, char * str, char * epilog )
{
    if( hOut != INVALID_HANDLE_VALUE )
    {
        DWORD dwTemp;

        if( prolog )
            WriteFile( hOut, prolog, strlength( prolog ), &dwTemp, NULL );
        if( str )
            WriteFile( hOut, str, strlength( str ), &dwTemp, NULL );
        if( epilog )
            WriteFile( hOut, epilog, strlength( epilog ), &dwTemp, NULL );
    }
}

void __cdecl mainCRTStartup()
{
    UINT code = 1;
    DWORD dwTemp;
    wchar_t * argv[3];
    wchar_t * str[3];
    unsigned counter;
    unsigned quanter;
    winhttp_handler h;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hOut = INVALID_HANDLE_VALUE;
    UINT page;

    hOut = GetStdHandle( STD_OUTPUT_HANDLE );

    if( 3 != strbreaker( GetCommandLineW(), (wchar_t **)&argv, 3, ' ', '"' ) )
    {
        strlogger( hOut, LOG_ERR_PROLOG, LOG_ERR_BAD_CMD, LOG_ERR_EPILOG );
        goto end;
    }

    memzero( &h, sizeof( winhttp_handler ) );

    h.url = argv[1];
    h.isSSL = h.url[4] == 's';

    memcopy( h.bbChunk, argv[1], ( argv[2] - argv[1] ) * sizeof( wchar_t ) );

    if( 3 != strbreaker( (wchar_t *)h.bbChunk, (wchar_t **)&str, 3, '/', '#' ) )
    {
        strlogger( hOut, LOG_ERR_PROLOG, LOG_ERR_BAD_CMD, LOG_ERR_EPILOG );
        goto end;
    }

    h.url_get = &h.url[str[2] - str[0] - 1];

    counter = strbreaker( str[1], (wchar_t **)&str, 2, ':', '#' );

    if( counter == 1 )
        h.port = h.isSSL ? 443 : 80;
    else if( counter == 2 )
        h.port = (INTERNET_PORT)str2num( str[1] );
    else
    {
        strlogger( hOut, LOG_ERR_PROLOG, LOG_ERR_BAD_CMD, LOG_ERR_EPILOG );
        goto end;
    }

    h.server = str[0];

    counter = 0;
    quanter = 1024 * 1024 / 50 / sizeof( h.bbChunk ) + 1;

    for( ;; )
    {
        dwTemp = winhttp_exec( &h );

        if( dwTemp != S_OK )
        {
            if( 0 != ( h.dwChunk = FormatMessageW( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                dwTemp, MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ), (LPWSTR)h.bbChunk, sizeof( h.bbChunk ) / 2, NULL ) ) ||

                0 != ( h.dwChunk = FormatMessageW( FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, (VOID *)GetModuleHandleA( "winhttp.dll" ),
                dwTemp, MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ), (LPWSTR)h.bbChunk, sizeof( h.bbChunk ) / 2, NULL ) ) )
            {
                if( h.dwChunk * 2 < sizeof( h.bbChunk ) &&
                    WideCharToMultiByte( GetConsoleOutputCP(), 0, (LPWSTR)h.bbChunk, -1, (LPSTR)h.bbChunk + sizeof( h.bbChunk ) / 2, sizeof( h.bbChunk ) / 2, NULL, NULL ) )
                    strlogger( hOut, LOG_ERR_PROLOG, h.bbChunk + sizeof( h.bbChunk ) / 2, NULL );
            }
            else
            {
                strlogger( hOut, LOG_ERR_PROLOG, LOG_ERR_WINHTTP, LOG_ERR_EPILOG );
            }

            goto end;
        }

        if( hFile == INVALID_HANDLE_VALUE )
        {
            hFile = CreateFileW( argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL );

            if( hFile == INVALID_HANDLE_VALUE )
            {
                strlogger( hOut, LOG_ERR_PROLOG, LOG_ERR_CREATEFILE, LOG_ERR_EPILOG );
                goto end;
            }

            if( h.dwTotal && h.dwTotal > 1024 * 1024 )
                quanter = h.dwTotal / 50 / sizeof( h.bbChunk ) + 1;

            strlogger( hOut, LOG_DOWNLOAD_PROLOG, NULL, NULL );
            if( h.dwTotal )
                strlogger( hOut, LOG_DOWNLOAD_SIZE_PROLOG, num2bytesize( h.dwTotal ), NULL );
            strlogger( hOut, NULL, NULL, LOG_DOWNLOAD_EPILOG );
        }

        if( h.dwChunk == 0 )
        {
            if( !h.dwTotal )
                strlogger( hOut, LOG_DOWNLOAD_SIZE_PROLOG, num2bytesize( h.dwLoaded ), NULL );

            strlogger( hOut, LOG_SUCCESS, NULL, NULL );
            break;
        }

        if( !WriteFile( hFile, h.bbChunk, h.dwChunk, &dwTemp, NULL ) || h.dwChunk != dwTemp )
        {
            strlogger( hOut, LOG_ERR_PROLOG, LOG_ERR_WRITEFILE, LOG_ERR_EPILOG );
            goto end;
        }

        counter++;

        if( counter % quanter == 0 )
            strlogger( hOut, LOG_DOWNLOADING, NULL, NULL );
    }

    code = 0;

end:

    ExitProcess( code );
}
