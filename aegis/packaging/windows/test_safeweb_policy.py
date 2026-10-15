#!/usr/bin/env python3
"""Exercise the exact helper URL/CRT quoting functions on a non-Windows host.

This test compiles extracted pure functions from safeweb.c; it does not simulate
AppContainer, Win32 child creation, Tor, clipboard, or native acceptance.
"""
import pathlib
import subprocess
import tempfile
import unittest

SOURCE=pathlib.Path(__file__).with_name('safeweb.c')

class NativePolicyTest(unittest.TestCase):
    def test_url_policy_and_windows_crt_argument_quoting(self):
        source=SOURCE.read_text()
        pure=source[source.index('static BOOL valid_url('):source.index('static wchar_t *minimal_environment(')]
        prelude=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <wchar.h>
#include <stddef.h>
#define BOOL int
#define FALSE 0
#define TRUE 1
#define URL_CAP 4096
#define PATH_CAP 32768
#define _wcsnicmp wcsncasecmp
'''
        harness=r'''
int main(void) {
  assert(valid_url(L"https://example.org/a?x=1&y=2#x"));
  assert(valid_url(L"HTTPS://Example.ORG:443/"));
  assert(valid_url(L"http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"));
  assert(valid_url(L"http://www.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"));
  const wchar_t *bad[]={L"file:///C:/cmd.exe",L"javascript:alert(1)",L"about:config",
    L"https://localhost/",L"https://a.localhost/",L"https://127.0.0.1/",
    L"https://[::1]/",L"http://example.org/",L"https://x/",L"https://-a.com/",
    L"https://example.org:0/",L"https://example.org:65536/",L"https://example.org:1x/",
    L"https://u:p@example.org/",L"https://example.org/\" -profile bad",
    L"https://example.org/\\bad",L"https://example.org/\n",L"https://bad.onion/",
    L"https://example.org/ --command",L"https://example.org\tbad/"};
  for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++)assert(!valid_url(bad[i]));
  wchar_t output[PATH_CAP];size_t used=0;
  assert(add_arg(output,&used,L"C:\\Users\\User Name\\Browser\\firefox.exe"));
  assert(add_arg(output,&used,L"https://example.org/?x=%22&y=$x"));
  assert(!wcscmp(output,L"\"C:\\Users\\User Name\\Browser\\firefox.exe\" \"https://example.org/?x=%22&y=$x\""));
  used=0;assert(quote_arg(output,PATH_CAP,&used,L"a\\\"b\\"));
  assert(!wcscmp(output,L"\"a\\\\\\\"b\\\\\""));
  used=0;assert(quote_arg(output,PATH_CAP,&used,L""));assert(!wcscmp(output,L"\"\""));
  used=0;assert(!quote_arg(output,3,&used,L"too big"));
  return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='aegis-winpolicy-') as tmp:
            code=pathlib.Path(tmp)/'policy.c';exe=pathlib.Path(tmp)/'policy'
            code.write_text(prelude+pure+harness)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-o',str(exe),str(code)],check=True)
            subprocess.run([str(exe)],check=True)

if __name__=='__main__': unittest.main()
