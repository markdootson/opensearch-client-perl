use Test::More;

BEGIN { use_ok('OpenSearch::Client::Hash') }

ok $h = OpenSearch::Client::Hash->new(), "new hash";

for my $testplan (
    
    { params => { password => 'my password' },
     expecterror => '',
     hashlength  => 118, name => 'good default type' },
    
    { params => { password => 'my password', type => 'argon2id' },
     expecterror => '',
     hashlength  => 118, name => 'good argon2id type' },
    
    { params => { password => 'my password', type => 'argon2d' },
     expecterror => '',
     hashlength  => 117, name => 'good argon2d type' },
    
    { params => { password => 'my password', type => 'argon2i' },
     expecterror => '',
     hashlength  => 117, name => 'good argon2i type' },
    
    { params => { password => '' },
     expecterror => 'you must provide a password',
     hashlength => 0, name => 'missing password' },
    
    { params => { password => 'my password', type => 'argon2z' },
     expecterror => "invalid type 'argon2z' : valid options are argon2i, argon2d or argon2id",
     hashlength  => 0, name => 'bad argon2 type' },
    
    { params => { password => 'my password', iterations => 'two' },
     expecterror => 'Invalid iterations "two". Must be an integer',
     hashlength  => 0, name => 'iterations is text' },
    
    { params => { password => 'my password', length => 'two' },
     expecterror => 'Invalid length "two". Must be an integer',
     hashlength  => 0, name => 'length is text' },
    
    { params => { password => 'my password', memory => 'two' },
     expecterror => 'Invalid memory "two". Must be an integer',
     hashlength  => 0, name => 'memory is text' },
    
    { params => { password => 'my password', iterations => 10 },
     expecterror => '',
     hashlength  => 119, name => 'iterations 10' },
    
    { params => { password => 'my password', memory => 512 },
     expecterror => '',
     hashlength  => 116, name => 'memory 512' },
    
    { params => { password => 'my password', memory => 131072 },
     expecterror => '',
     hashlength  => 119, name => 'memory 131072' },
    
    { params => { password => 'my password', length => 64 },
     expecterror => '',
     hashlength  => 161, name => 'length 64' },
    
) {
    my $thash = $h->create_argon2_password_hash(%{ $testplan->{params} });
    is( $h->errorstring, $testplan->{expecterror}, $testplan->{name} . ' error string' );
    is( length($thash), $testplan->{hashlength}, $testplan->{name} . ' hash length');
}

done_testing;
