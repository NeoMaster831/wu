void __fastcall sub_559EBC003A75(Node *a1)
{
  signed __int64 v1; // rax

  v1 = sys_mkdir((const char *)&a1->fd->content, 511);
  free((void *)a1->content);
}