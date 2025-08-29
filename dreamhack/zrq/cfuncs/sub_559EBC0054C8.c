void __fastcall sub_559EBC0054C8(Node *a1)
{
  Node *fd; // rbx

  a1->fd->content <<= 8;
  fd = a1->fd->fd->fd->fd->fd->fd->fd->fd->fd;
  fd->content = sys_mmap(0, 0x2000u, 3u, 0x22u, 0, 0);
  *(_QWORD *)(fd->content + 32) = fd->content + 4096;
  free(&off_559EBC20CD50);
}