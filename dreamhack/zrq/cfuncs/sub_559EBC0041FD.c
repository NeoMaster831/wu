void __fastcall sub_559EBC0041FD(Node *a1)
{
  char *content; // rbx
  _UNKNOWN ****************v2; // rax

  content = (char *)a1->fd->fd->fd->fd->fd->content;
  if ( sprintf(content, "%s", (const char *)(a1->fd->fd->fd->content + 2)) > 0 )
  {
    a1->fd->content = (size_t)&off_559EBC20C690;
    if ( content[2] )
      v2 = (_UNKNOWN ****************)&off_559EBC20B910;
    else
      v2 = &off_559EBC20C7E0;
    free(v2);
  }
  else
  {
    free(&off_559EBC20C690);
  }
}