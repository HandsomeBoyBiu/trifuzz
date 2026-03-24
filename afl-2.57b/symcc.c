#include "symcc.h"

/*
// after fork
void symcc_init() {
  return;
}

void symcc_worker() {

  char buf[SYMCC_COMMAND_LEN];
  int pos = 0;
  int in_command = 0;

  while (1) { 
    // "#<command>@<data>$" format
    char ch;
    ssize_t n = read(symcc_pipefd[0], &ch, 1);

    if (n <= 0) {
      perror("read symcc_pipefd");
      break;
    }

    if (ch == '#') {
      in_command = 1;
      pos = 0;
      continue;
    }

    if (!in_command) {
      continue;
    }

    if (ch == '$') {
      buf[pos] = '\0';
      // 此时 buf 中内容是 <command>@<data>
      char *sep = strchr(buf, '@');
      if (!sep) {
        fprintf(stderr, "Invalid command format (missing '@'): %s\n", buf);
        continue;
      }

      *sep = '\0';
      char *cmd = buf;
      char *data = sep + 1;

      fprintf(stderr, "[symcc_worker] Received command: '%s'\n", cmd);
      fprintf(stderr, "[symcc_worker] With data: '%s'\n", data);

      // TODO: 根据 cmd 调用实际处理逻辑

      memset(buf, 0, SYMCC_COMMAND_LEN);
      in_command = 0;
      pos = 0;
      continue;
    }
  }
  return;
}

void symcc_one(char* buf) {
  u8* symcc_output_dir = NULL;

  // 创建目录
  symcc_output_dir = alloc_printf("%s/%s/%s%s", out_dir, SYMCC_OUTPUT, buf, "_stest");  

  int i = 0;
  while (mkdir(symcc_output_dir, 0700)) {
    free(symcc_output_dir);
    symcc_output_dir = alloc_printf("%s/%s/%s%s%d", out_dir, SYMCC_OUTPUT, buf, "_stest", i);
  }
  setenv("SYMCC_OUTPUT_DIR", symcc_output_dir, 1);

  // 运行CE

  // 评估生成的testcase

  // 将interesting testcases写入queue（？）
  return;
}

*/


