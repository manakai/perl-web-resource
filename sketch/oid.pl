use strict;
use warnings;
use Net::SSLeay;

my $in = shift;

my $obj_obj = Net::SSLeay::OBJ_txt2obj $in or die "Bad input";
#my $obj_nid = Net::SSLeay::OBJ_txt2nid $in or die "Bad input";
my $obj_nid = Net::SSLeay::OBJ_obj2nid $obj_obj or warn "No nid";
my $obj_ln = Net::SSLeay::OBJ_nid2ln $obj_nid;
my $obj_sn = Net::SSLeay::OBJ_nid2sn $obj_nid;
#my $obj_obj = Net::SSLeay::OBJ_nid2obj $obj_nid;
my $obj_id = Net::SSLeay::OBJ_obj2txt ($obj_obj, 1);

warn "Short: $obj_sn\n";
warn "Long:  $obj_ln\n";
warn "Text:  $obj_id\n";
