void __fastcall sub_559EBC00467E(Node *a1)
{
  Node *fd; // r12
  Node *v2; // rbx

  fd = a1->fd->fd->fd->fd->fd;
  v2 = fd->fd->fd->fd;
  v2->content = sys_mmap(0, 0x2000u, 3u, 0x22u, 0, 0);
  fd->content = v2->content + 4096;
  v2->fd->content = (size_t)malloc(0x90u);
}