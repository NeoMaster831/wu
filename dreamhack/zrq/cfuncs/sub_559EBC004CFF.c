void __fastcall sub_559EBC004CFF(Node *a1)
{
  signed __int64 v1; // r9
  __int64 v2; // r8

  v1 = sys_open((const char *)a1->fd->fd->fd->fd->fd->content, 0, 420);
  *(_QWORD *)(v2 + 24) = v1;
  if ( (a1->fd->content & 0x8000000000000000LL) != 0LL )
    free(&off_559EBC20C6F0);
}