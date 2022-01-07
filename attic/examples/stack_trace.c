// Source: https://gist.github.com/banthar/1343977
// stack_trace.c
//
// See also
//   https://github.com/strace/strace/blob/master/src/unwind-libdw.c
//   https://github.com/ganboing/elfutils/tree/master/libdwfl

// Install dependencies: sudo apt install libunwind-dev libdw-dev -y
// Compile:              gcc stack_trace.c -ldw -lunwind -g -o stack_trace


#define UNW_LOCAL_ONLY

#include <elfutils/libdwfl.h>
#include <libunwind.h>

#include <errno.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include <assert.h>



static void debug_info(FILE* out, const void* ip, pid_t pid) {

/* -- 0. Init -- */
  // char *debuginfo_path = NULL;
  Dwfl_Callbacks callbacks = {
    .find_elf = dwfl_linux_proc_find_elf,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    // .debuginfo_path = &debuginfo_path
  };
  Dwfl* dwfl = dwfl_begin(&callbacks);
  assert(NULL != dwfl);

  assert(!dwfl_linux_proc_report (dwfl, pid));
  assert(!dwfl_report_end (dwfl, NULL, NULL));


  // int r = dwfl_linux_proc_attach(dwfl, tcp->pid, true); // cleanup on failure !


  Dwarf_Addr addr = (uintptr_t)ip;
  Dwfl_Module* module = dwfl_addrmodule (dwfl, addr);

/* -- Get function name -- */
  const char* function_name = dwfl_module_addrname(module, addr);
  fprintf(out, "%s(", function_name);


  Dwfl_Line *line = dwfl_getsrc (dwfl, addr);
  if (NULL != line) {
    int nline;
    Dwarf_Addr addr;
    const char* filename = dwfl_lineinfo (line, &addr, &nline, NULL, NULL, NULL);
    fprintf(out, "%s:%d", /*strrchr(filename,'/') +1*/ filename, nline);
  } else {
    // fprintf(out,"%p", ip);
    // Here's how to get the .so name when the file name is not available:
    const char *module_name = dwfl_module_info(module, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    fprintf(out, "in %s", module_name);
  }

  dwfl_end(dwfl);
}


static void __attribute__((noinline)) print_stacktrace(FILE* out, int skip) {
  unw_context_t uc;
  unw_getcontext(&uc);

  unw_cursor_t cursor;
  unw_init_local(&cursor, &uc);


  while(unw_step(&cursor) > 0) {
  /* -- Get IP -- */
    unw_word_t ip;
    unw_get_reg(&cursor, UNW_REG_IP, &ip);

/* ---------------- ---------------- ---------------- ---------------- ---------------- ---------------- ---------------- ---------------- */
    if (skip <= 0) {
      fprintf(out, "\tat ");
  /* -- Get function-name + filename + line-nr -- */
      debug_info(out, (void*)(ip - 4), getpid());
      fprintf(out, ")\n");
    }
/* ---------------- ---------------- ---------------- ---------------- ---------------- ---------------- ---------------- ---------------- */


  /* -- Get name of function (which created stackframe) -- */
    unw_word_t offset;
    char name[32];
    assert(unw_get_proc_name(&cursor, name, sizeof(name), &offset) == 0);

    if (strcmp(name, "main") == 0) break;

    skip--;
  }
}





/* -- Test -- */
void c(void) {
  print_stacktrace(stdout, 0);
}

void b(void) {
  c();
}

void a(void) {
  b();
}

int main(int argc, char*argv[]) {
  a();
}
