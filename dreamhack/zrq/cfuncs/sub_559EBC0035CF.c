void __fastcall sub_559EBC0035CF(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd->fd->fd->fd->fd->fd->fd;
  fd->content = sys_mmap(0, a1->fd->fd->fd->fd->content + 1, 3u, 0x22u, 0, 0);
}