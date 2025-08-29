void __fastcall sub_559EBC003064(Node *a1)
{
  if ( sprintf((char *)a1->fd->fd->fd->fd->fd->fd->content, "%s", (const char *)(a1->fd->fd->fd->fd->content + 2)) == 2 )
    free(&off_559EBC20C7E0);
  *(_BYTE *)(a1->fd->fd->fd->fd->content + 2) = 0;
}