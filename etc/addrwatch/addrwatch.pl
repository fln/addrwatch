#!/usr/bin/perl

use Net::SMTP;
 use POSIX;

POSIX::setsid or die "setsid: $!";
$pid = fork ();
   if ($pid < 0) {
      die "fork: $!";
   } elsif ($pid) {
      exit 0;
   }
   chdir "/";
   umask 0;
   foreach (0 .. (POSIX::sysconf (&POSIX::_SC_OPEN_MAX) || 1024))
      { POSIX::close $_ }
   open (STDIN, "</dev/null");
   open (STDOUT, ">/dev/null");
   open (STDERR, ">&STDOUT");

   open(ADDRWATCH,"addrwatch -p /var/run/addrwatch.pid -r 60 -u nobody eth0 eth0.8 eth0.10 eth3.12 eth3.100 eth3.101 eth3.102 eth3.103 --ipv4-only |");


while(<ADDRWATCH>){
    chomp();
    if (m/ND_NS|ND_NA|ND_DAD/) {
        $sender = Net::SMTP->new("mail.qarea.com");
        $sender->mail('addrwatch@gate.qarea.org');
        $sender->to('admin@qarea.com');
        $sender->data();
        $sender->datasend('From: addrwatch@gate.qarea.com'."\n");
        $sender->datasend('To: admin@qarea.com'."\n");
        $sender->datasend("Subject: ARP Anomaly detected\n");
        $sender->datasend("\n");
        $sender->datasend("$_\n");
#	if (m/ARP_ACD/) {
#            $sender->datasend("ARP Address collision detection packet");
#        }
        if (m/ND_NS/) {
            $sender->datasend("Neighbor Solicitation packet");
        }
        if (m/ND_NA/) {
            $sender->datasend("Neighbor Advertisement packet");
        }
        if (m/ND_DAD/) {
            $sender->datasend("Duplicate Address Detection packet");
        }
        $sender->dataend();
    }
}
