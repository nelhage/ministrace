// Source: https://gist.github.com/banthar/1343977
// stack_trace.c
//
// Install dependencies: sudo apt-get install libelf-dev libdwarf-dev -y
// Compile:              gcc stack_trace.c -ldw -lunwind -g -o stack_trace

#define UNW_LOCAL_ONLY

#include <elfutils/libdwfl.h>
#include <libunwind.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

static void debugInfo(FILE* out,const void* ip)
{

  char *debuginfo_path=NULL;

  Dwfl_Callbacks callbacks={
    .find_elf=dwfl_linux_proc_find_elf,
    .find_debuginfo=dwfl_standard_find_debuginfo,
    .debuginfo_path=&debuginfo_path,
  };

  Dwfl* dwfl=dwfl_begin(&callbacks);
  assert(dwfl!=NULL);

  assert(dwfl_linux_proc_report (dwfl, getpid())==0);
  assert(dwfl_report_end (dwfl, NULL, NULL)==0);

  Dwarf_Addr addr = (uintptr_t)ip;

  Dwfl_Module* module=dwfl_addrmodule (dwfl, addr);

  const char* function_name = dwfl_module_addrname(module, addr);

  fprintf(out,"%s(",function_name);

  Dwfl_Line *line=dwfl_getsrc (dwfl, addr);
  if(line!=NULL)
  {
    int nline;
    Dwarf_Addr addr;
    const char* filename=dwfl_lineinfo (line, &addr,&nline,NULL,NULL,NULL);
    fprintf(out,"%s:%d",strrchr(filename,'/')+1,nline);
  }
  else
  {
    fprintf(out,"%p",ip);
  }
}

static void __attribute__((noinline)) printStackTrace(FILE* out, int skip)
{

  unw_context_t uc;
  unw_getcontext(&uc);

  unw_cursor_t cursor;
  unw_init_local(&cursor, &uc);

  while(unw_step(&cursor)>0)
  {

    unw_word_t ip;
    unw_get_reg(&cursor, UNW_REG_IP, &ip);

    unw_word_t offset;
    char name[32];
    assert(unw_get_proc_name(&cursor, name,sizeof(name), &offset)==0);

    if(skip<=0)
    {
      fprintf(out,"\tat ");
      debugInfo(out,(void*)(ip-4));
      fprintf(out,")\n");
    }

    if(strcmp(name,"main")==0)
      break;

    skip--;

  }

}

void c(void)
{
  printStackTrace(stdout,0);
}

void b(void)
{
  c();
}

void a(void)
{
  b();
}

int main(int argc, char*argv[])
{
  a();
}





/*
andrewrk commented on 31 Jul 2015

Yes thank you very much for this snippet.

Here's how to get the .so name when the file name is not available:

--- stacktrace.c    2015-07-31 00:08:16.844089668 -0700
+++ stacktrace.c    2015-07-31 00:08:11.280271152 -0700
@@ -50,7 +50,9 @@
    }
    else
    {
-       fprintf(out,"%p",ip);
+        const char *module_name = dwfl_module_info(module,
+                NULL, NULL, NULL, NULL, NULL, NULL, NULL);
+        fprintf(out, "in %s", module_name);
    }
 }
*/
