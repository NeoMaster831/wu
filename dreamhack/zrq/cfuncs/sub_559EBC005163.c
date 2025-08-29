void __fastcall sub_559EBC005163(Node *a1)
{
  size_t content; // rbx

  content = a1->fd->fd->fd->fd->fd->fd->fd->content;
  a1->fd->content = sprintf(*(char **)(content + 32), "%s/", (const char *)a1->fd->fd->content)
                  + *(_QWORD *)(content + 32);
  *(_QWORD *)(content + 8) = 65;
  *(_QWORD *)(content + 72) = 65;
  *(_QWORD *)(content + 136) = 65;
  *(_QWORD *)(content + 16) = 0;
  free((void *)(content + 16));
  free(&off_559EBC20C450);
}