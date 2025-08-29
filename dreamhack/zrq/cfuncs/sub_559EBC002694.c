void __fastcall sub_559EBC002694(Node *a1)
{
  signed __int64 v1; // rax
  const char *envp; // [rsp+18h] [rbp-38h] BYREF
  const char *argv[6]; // [rsp+20h] [rbp-30h] BYREF

  argv[5] = (const char *)__readfsqword(0x28u);
  argv[0] = "/bin/sh";
  argv[1] = "-c";
  argv[2] = "rm /tmp/.zrq/*";
  argv[3] = 0;
  envp = 0;
  v1 = sys_execve("/bin/sh", argv, &envp);
}