void __fastcall sub_559EBC0033D3(Node *a1)
{
  a1->fd->fd->content = (size_t)malloc(0x110u);
  if ( sys_read(a1->fd->content, (char *)(a1->fd->fd->content + 32), 8u) != 8 )
    free(&off_559EBC20C840);
}