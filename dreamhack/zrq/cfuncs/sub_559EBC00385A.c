void __fastcall sub_559EBC00385A(Node *a1)
{
  signed __int64 v1; // rax
  __int64 v2; // r8

  v1 = sys_lseek(a1->fd->fd->fd->fd->fd->fd->fd->fd->fd->content, 0, 2u);
  *(_QWORD *)(v2 + 24) = 2 * v1;
}