void __fastcall sub_559EBC002B67(Node *a1)
{
  signed __int64 v1; // rax
  __int64 v2; // r8

  v1 = sys_open((const char *)a1->fd->fd->fd->fd->fd->content, 0, 0);
  *(_QWORD *)(v2 + 24) = v1;
  free((void *)a1->content);
}