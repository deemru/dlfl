#include <windows.h>
#include <winhttp.h>

#pragma comment( lib, "kernel32.lib")
#pragma comment( lib, "winhttp.lib")

void memzero( void * mem, size_t size ) // anti memset
{
    while( size-- )
    {
        ( (volatile char *)mem )[size] = 0;
    }
}

void memcopy( void * dst, const void * src, size_t size ) // anti memcpy
{
    while( size-- )
    {
        ( (volatile char *)dst )[size] = ( (volatile char *)src )[size];
    }
}

unsigned strlength( const char * str ) // anti strlen
{
    unsigned length = 0;

    while( 0 != *str++ )
        length++;

    return length;
}

#define WINHTTP_TIMEOUT 9999
#define WINHTTP_CHUNK   1280
#define WINHHTP_AGENT   L"WinHTTP (github/deemru/dlfl)"

typedef struct
{
    PWSTR url;
    PWSTR url_get;
    PWSTR server;
    INTERNET_PORT port;
    BOOL isSSL;

    PWSTR filename;
    BYTE bbChunk[WINHTTP_CHUNK];
    DWORD dwChunk;
    DWORD dwLoaded;
    DWORD dwTotal;

    HINTERNET hSession;
    HINTERNET hConnect;
    HINTERNET hRequest;
}
winhttp_handler;

DWORD winhttp_exec( winhttp_handler * h )
{
    BOOL isOK = FALSE;

    if( h->hRequest )
        goto download;

    h->hSession = WinHttpOpen( WINHHTP_AGENT, WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS,
                               0 );

    if( !h->hSession )
        goto end;

    h->hConnect = WinHttpConnect( h->hSession, h->server, h->port, 0 );

    if( !h->hConnect )
        goto end;

    h->hRequest = WinHttpOpenRequest( h->hConnect, L"GET", h->url_get, NULL,
                                      WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      h->isSSL ? WINHTTP_FLAG_SECURE : 0 );

    if( !h->hRequest )
        goto end;

    isOK = WinHttpSetTimeouts( h->hRequest, 0, WINHTTP_TIMEOUT, WINHTTP_TIMEOUT,
                               WINHTTP_TIMEOUT );

    if( !isOK )
        goto end;

    {
        WINHTTP_PROXY_INFO ProxyInfo;

        isOK = FALSE;

        {
            WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ProxyConfig;

            memzero( &ProxyConfig, sizeof( ProxyConfig ) );
            ProxyConfig.fAutoDetect = TRUE;

            if( WinHttpGetIEProxyConfigForCurrentUser( &ProxyConfig ) )
            {
                if( ProxyConfig.lpszProxy && ProxyConfig.lpszProxy[0] )
                {
                    ProxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                    ProxyInfo.lpszProxy = ProxyConfig.lpszProxy;
                    ProxyInfo.lpszProxyBypass = ProxyConfig.lpszProxyBypass;

                    if( WinHttpSetOption( h->hRequest, WINHTTP_OPTION_PROXY,
                                          &ProxyInfo, sizeof( ProxyInfo ) ) )
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
            AutoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP |
                                                 WINHTTP_AUTO_DETECT_TYPE_DNS_A;
            AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

            if( WinHttpGetProxyForUrl( h->hSession, h->url, &AutoProxyOptions,
                                       &ProxyInfo ) )
            {
                if( WinHttpSetOption( h->hRequest, WINHTTP_OPTION_PROXY,
                                      &ProxyInfo, sizeof( ProxyInfo ) ) )
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

    if( h->isSSL )
    {
        isOK = WinHttpSetOption( h->hRequest, 
                                 WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                                 WINHTTP_NO_CLIENT_CERT_CONTEXT, 0 );

        if( !isOK )
            goto end;
    }

    isOK = WinHttpSendRequest( h->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0 );

    if( !isOK )
        goto end;

    isOK = WinHttpReceiveResponse( h->hRequest, NULL );

    if( !isOK )
        goto end;

    {
        DWORD dwValue;
        DWORD dwSize = sizeof( dwValue );
        
        isOK = WinHttpQueryHeaders( h->hRequest, WINHTTP_QUERY_STATUS_CODE |
                                    WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &dwValue,
                                    &dwSize, WINHTTP_NO_HEADER_INDEX );

        if( !isOK )
            goto end;

        if( dwValue != HTTP_STATUS_OK )
        {
            isOK = 0;
            SetLastError( (DWORD)NTE_NOT_FOUND );
            goto end;
        }

        isOK = WinHttpQueryHeaders( h->hRequest, WINHTTP_QUERY_CONTENT_LENGTH |
                                    WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &dwValue,
                                    &dwSize, WINHTTP_NO_HEADER_INDEX );

        if( isOK )
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
        DWORD dwRetCode = isOK ? S_OK : GetLastError();

        if( h->hRequest ) WinHttpCloseHandle( h->hRequest );
        if( h->hConnect ) WinHttpCloseHandle( h->hConnect );
        if( h->hSession ) WinHttpCloseHandle( h->hSession );

        return dwRetCode;
    }
}

unsigned wstr2num( const wchar_t * wstr )
{
    unsigned u = 0;
    wchar_t c;

    while( 0 != ( c = *wstr++ ) )
        u = u * 10 + c - '0';

    return u;
}

char * wstr2str( const wchar_t * wstr )
{
    static char buf[MAX_PATH];
    return WideCharToMultiByte( GetConsoleOutputCP(), 0, wstr,-1, buf,
                                sizeof( buf ), NULL, NULL ) ? buf : NULL;
}

/*
Download "___________________________...___________________________" (13337 KB)
*/
#define NAME_HALF 27
#define NAME_FULL ( NAME_HALF + 3 + NAME_HALF + 1)
#define NAME_BRK "..."

char * wstr2name( const wchar_t * wstr )
{
    static char buf[NAME_FULL];
    char * str = wstr2str( wstr );
    int shift;

    if( !str )
        return NAME_BRK;

    shift = sizeof( buf ) - 1 - strlength( str );

    if( shift < 0 )
    {
        memcopy( buf, str, NAME_HALF );
        memcopy( buf + NAME_HALF, NAME_BRK, 3 );
        memcopy( buf + NAME_HALF + 3,
                 str + sizeof( buf ) - 1 - shift - NAME_HALF, NAME_HALF + 1 );
    }
    else
    {
        memcopy( buf, str, sizeof( buf ) - shift );
    }

    return buf;
}

char * num2str_bs( unsigned u )
{
    static char bytesize_MB[] = "_____ MB";
    static char bytesize_KB[] = "_____ KB";
    static char bytesize_B[]  = "_____ B";

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

unsigned wstrbrk( wchar_t * wstr, wchar_t ** wstrs, unsigned max,
                  wchar_t breaker, wchar_t quote )
{
    wchar_t c;
    wchar_t is_begin = 0;
    wchar_t is_quote = 0;
    unsigned u = 0;

    while( 0 != ( c = *wstr ) )
    {
        if( !is_begin )
        {
            if( c == breaker )
            {
                wstr++;
                continue;
            }

            else
            {
                if( u >= max )
                    return max;

                is_begin = 1;
                if( c == quote )
                {
                    is_quote = 1;
                    wstr++;
                }
                wstrs[u] = wstr;
                continue;
            }
        }

        if( c == quote )
        {
            if( !is_quote )
                return 0;

            is_begin = 0;
            is_quote = 0;
            *wstr = 0;
            wstr++;
            u++;
            continue;
        }

        if( is_quote )
        {
            wstr++;
            continue;
        }

        if( c == breaker )
        {
            is_begin = 0;
            *wstr = 0;
            wstr++;
            u++;
            continue;
        }

        wstr++;
    }

    if( is_begin )
        u++;

    return u;
}

#define LOG_ERR_PROLOG     "ERROR: "
#define LOG_ERR_BAD_CMD    "Bad command line"
#define LOG_ERR_WINHTTP    "WinHTTP unknown error"
#define LOG_ERR_CREATEFILE "CreateFile failed"
#define LOG_ERR_WFILE      "WriteFile failed"
#define LOG_ERR_EPILOG     "\r\n"

void strlog( HANDLE hOut, unsigned count, ... )
{
    if( hOut != INVALID_HANDLE_VALUE )
    {
        va_list strs;
        va_start( strs, count );

        for( ; count; count-- )
        {
            DWORD dw;
            char * str = va_arg( strs, char * );

            if( str )
                WriteFile( hOut, str, strlength( str ), &dw, NULL );
        }

        va_end( strs );
    }
}

void __cdecl mainCRTStartup()
{
    winhttp_handler h;
    unsigned        cnt;
    unsigned        qnt;
    HANDLE          hFile = INVALID_HANDLE_VALUE;
    HANDLE          hOut = INVALID_HANDLE_VALUE;

    memzero( &h, sizeof( winhttp_handler ) );

    hOut = GetStdHandle( STD_OUTPUT_HANDLE );

    {
        wchar_t * wstrs[3];

        if( 3 != wstrbrk( GetCommandLineW(), (wchar_t **)&wstrs, 3, ' ', '"' ) )
        {
            strlog( hOut, 3, LOG_ERR_PROLOG, LOG_ERR_BAD_CMD, LOG_ERR_EPILOG );
            goto end;
        }

        memzero( &h, sizeof( winhttp_handler ) );

        h.url = wstrs[1];
        h.isSSL = h.url[4] == 's';
        h.filename = wstrs[2];
        h.url_get = L"/";

        memcopy( h.bbChunk, wstrs[1], 2 * ( wstrs[2] - wstrs[1] ) );
    }

    {
        wchar_t * wstrs[3];

        cnt = wstrbrk( (wchar_t *)h.bbChunk, (wchar_t **)&wstrs, 3, '/', '#' );

        if( cnt == 3 )
        {
            h.url_get = &h.url[wstrs[2] - wstrs[0] - 1];
        }
        else if( cnt != 2 )
        {
            strlog( hOut, 3, LOG_ERR_PROLOG, LOG_ERR_BAD_CMD, LOG_ERR_EPILOG );
            goto end;
        }

        cnt = wstrbrk( wstrs[1], (wchar_t **)&wstrs, 2, ':', '#' );

        h.server = wstrs[0];

        if( cnt == 1 )
        {
            h.port = h.isSSL ? 443 : 80; // default choice
        }
        else if( cnt == 2 )
        {
            h.port = (INTERNET_PORT)wstr2num( wstrs[1] );
        }
        else
        {
            strlog( hOut, 3, LOG_ERR_PROLOG, LOG_ERR_BAD_CMD, LOG_ERR_EPILOG );
            goto end;
        }
    }

    cnt = 0;
    qnt = 1024 * 1024 / 64 / sizeof( h.bbChunk ) + 1;

    for( ;; )
    {
        DWORD dw = winhttp_exec( &h );

        if( dw != S_OK )
        {
            if(
                ( h.dwChunk = 
                  FormatMessageW( FORMAT_MESSAGE_FROM_SYSTEM |
                                  FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dw,
                                  MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
                                  (PWSTR)h.bbChunk, sizeof( h.bbChunk ) / 2,
                                  NULL )
                ) != S_OK
                || 
                ( h.dwChunk =
                  FormatMessageW( FORMAT_MESSAGE_FROM_HMODULE |
                                  FORMAT_MESSAGE_IGNORE_INSERTS,
                                  (VOID *)GetModuleHandleA( "winhttp.dll" ), dw,
                                  MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
                                  (PWSTR)h.bbChunk, sizeof( h.bbChunk ) / 2,
                                  NULL )
                ) != S_OK
              )
            {
                strlog( hOut, 2, LOG_ERR_PROLOG, wstr2str( (PWSTR)h.bbChunk ) );
            }
            else
            {
                strlog( hOut, 3, LOG_ERR_PROLOG, LOG_ERR_WINHTTP,
                        LOG_ERR_EPILOG );
            }

            goto end;
        }

        if( hFile == INVALID_HANDLE_VALUE )
        {
            hFile = CreateFileW( h.filename, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, 0, NULL );

            if( hFile == INVALID_HANDLE_VALUE )
            {
                strlog( hOut, 3, LOG_ERR_PROLOG, LOG_ERR_CREATEFILE,
                        LOG_ERR_EPILOG );
                goto end;
            }
            
            strlog( hOut, 3, "Download \"", wstr2name( h.url ), "\"" );

            if( h.dwTotal && h.dwTotal > 1024 * 1024 )
                qnt = h.dwTotal / 64 / sizeof( h.bbChunk ) + 1;

            if( h.dwTotal )
                strlog( hOut, 3, " (", num2str_bs( h.dwTotal ), ")" );

            strlog( hOut, 1, "\r\n..." );
        }

        if( h.dwChunk == 0 )
        {
            if( !h.dwTotal )
                strlog( hOut, 5, " (", num2str_bs( h.dwLoaded ), ")" );

            strlog( hOut, 1, " OK\r\n" );

            CloseHandle( hFile );
            ExitProcess( 0 ); // SUCCESS
        }

        if( FALSE == WriteFile( hFile, h.bbChunk, h.dwChunk, &dw, NULL ) ||
            h.dwChunk != dw )
        {
            strlog( hOut, 3, LOG_ERR_PROLOG, LOG_ERR_WFILE, LOG_ERR_EPILOG );
            goto end;
        }

        cnt++;

        if( cnt % qnt == 0 )
            strlog( hOut, 1, "." );
    }

end:

    if( hFile != INVALID_HANDLE_VALUE )
    {
        CloseHandle( hFile );
        DeleteFileW( h.filename );
    }

    ExitProcess( 1 );
}
