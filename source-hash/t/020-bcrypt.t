use Test::More;

BEGIN { use_ok('OpenSearch::Client::Hash') }

ok $h = OpenSearch::Client::Hash->new(), "new hash";

for my $testplan (
    
    { params => { password => 'my password' },
     expecterror => '',
     hashlength  => 60, name => 'good hash' },
    
    { params => { password => '' },
     expecterror => 'you must provide a password',
     hashlength => 0, name => 'missing password' },
    
    { params => { password => 'X' x 73 },
     expecterror => 'your password is longer than 72 characters',
     hashlength => 0, name => 'long password' },
    
    { params => { password => 'my password', type => '2x' },
     expecterror => "invalid type '2x' : valid options are 2y, 2a or 2b",
     hashlength => 0, name => 'bad type' },
    
    { params => { password => 'my password', rounds => '2' },
     expecterror => 'Invalid rounds "2". Must be an integer between 4 and 31 inclusive.',
     hashlength => 0, name => 'bad rounds' },
    
    { params => { password => 'my password', rounds => 'garbage' },
     expecterror => 'Invalid rounds "garbage". Must be an integer between 4 and 31 inclusive.',
     hashlength => 0, name => 'text rounds' },
    
    { params => { password => 'my password', rounds => 4 },
     expecterror => '',
     hashlength  => 60, name => 'rounds 4' },
    
) {
    my $thash = $h->create_bcrypt_password_hash(%{ $testplan->{params} });
    is( $h->errorstring, $testplan->{expecterror}, $testplan->{name} . ' error string' );
    is( length($thash), $testplan->{hashlength}, $testplan->{name} . ' hash length');
    
}


done_testing;
