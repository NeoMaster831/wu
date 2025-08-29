void __fastcall sub_559EBC005320(Node *a1)
{
  size_t content; // rbx
  signed __int64 v2; // rax

  content = a1->fd->content;
  **(_QWORD **)content = a1->fd->fd->fd->fd->fd->fd->fd;
  v2 = sys_write(*(_QWORD *)(*****(_QWORD *****)content + 24LL), (const char *)(*(_QWORD *)content + 17LL), 1u);
  *(_QWORD *)(*(_QWORD *)content + 16LL) = sub_559EBC00470D;
  free((void *)a1->content);
}