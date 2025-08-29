void __fastcall sub_559EBC003C3E(Node *a1)
{
  size_t content; // rbx

  content = a1->fd->fd->content;
  if ( realpath((const char *)(content + 4096), (char *)content) )
    qmemcpy((void *)(content + 4096), (const void *)content, 0x1000u);
  else
    free(&off_559EBC20C840);
}