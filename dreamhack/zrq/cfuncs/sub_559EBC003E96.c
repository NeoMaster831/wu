void __fastcall sub_559EBC003E96(Node *a1)
{
  if ( a1->content == 1 )
    ++a1->fd->content;
  else
    free(&off_559EBC20C150);
}