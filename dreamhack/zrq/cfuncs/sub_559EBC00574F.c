void __fastcall sub_559EBC00574F(Node *a1)
{
  signed __int64 v1; // rax
  __int64 v2; // r8

  v1 = sys_read(0, (char *)a1->fd->fd->content, 1u);
  *(_QWORD *)(v2 + 24) = v1;
  free(&off_559EBC20C2D0);
}