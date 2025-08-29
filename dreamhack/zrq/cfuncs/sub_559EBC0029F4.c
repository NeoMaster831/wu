void __fastcall sub_559EBC0029F4(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd->fd->fd->fd->fd;
  fd->content = sys_mmap(0, 9 * fd->fd->fd->content, 3u, 0x22u, 0, 0);
}