package wpblocker;

use nginx;
use Digest::MD5 qw(md5_hex);

sub get_file
{
	my $r = shift;
	my $net = "0.0.0";
	if ($r->remote_addr =~ /(.*)\.(.*)\.(.*)\.(.*)/)
	{
		$net = $1.".".$2.".".$3;
	}

	$host = md5_hex($r->variable("host"));

	return "/usr/local/wpblocker/var/$net-$host";

}

sub try_auth
{
	my $r = shift;
	my $login = "nobody";
	my $path = $r->variable("path");
	if ($r->variable("document_root") =~ /^\/home\/([a-zA-Z0-9]*)\/.*/)
	{
		$login = $1;
	}
	elsif ($r->variable("document_root") =~ /^\/var\/www\/([a-zA-Z0-9]*)\/.*/)
	{
		$login = $1;
	}
	
	if ($r->variable("arg_password") eq $login)
	{
		open FILE, ">", get_file($r);
		close FILE;
		$r->internal_redirect("/__wpblocker/$path/ok");
	}
	else
	{
		$r->variable("failed", "1");
		$r->internal_redirect("/__wpblocker/$path/form?failed=1");
	}
	return OK;
}

1;
__END__
