void __fastcall sub_559EBC004A02(Node *a1)
{
  if ( *(_BYTE *)(a1->fd->fd->content + a1->fd->fd->fd->fd->fd->fd->fd->content - 1) != 47 )
  {
    free(a1);
    --a1->fd->fd->content;
  }
}