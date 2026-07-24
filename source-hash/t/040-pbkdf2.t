use Test::More;

BEGIN { use_ok('OpenSearch::Client::Hash') }

ok $h = OpenSearch::Client::Hash->new(), "new hash";

for my $testplan (
    
    { params => { password => 'my password' },
     expecterror => '',
     hashlength  => 237, name => 'good password' },
    
    { params => { password => '' },
     expecterror => 'you must provide a password',
     hashlength => 0, name => 'missing password' },
    
    { params => { password => 'my password', function => 'MD5' },
     expecterror => q('MD5' is not a valid function. Valid functions are SHA1, SHA224, SHA256, SHA384, SHA512),
     hashlength  => 0, name => 'bad function' },
    
    { params => { password => 'my password', length => 'garbage' },
     expecterror => 'Invalid length "garbage". Must be an integer',
     hashlength  => 0, name => 'text length value' },
    
    { params => { password => 'my password', length => 257 },
     expecterror => q(A length of '257' bits cannot be encoded as bytes. Use a multiple of 8 ( 128, 224, 256, 384, 512 etc)),
     hashlength  => 0, name => 'text bits value' },
    
    { params => { password => 'my password', iterations => 'two' },
     expecterror => 'Invalid iterations "two". Must be an integer',
     hashlength  => 0, name => 'iterations is text' },
    
    ## tests use an insecure low number of iterations as that speeds up these tests 
    
    { params => { password => 'my password', length => 512, function => 'SHA1', iterations => '1000'  },
     expecterror => '',
     hashlength  => 278, name => 'L 512 F SHA1 I 1000' },
        
    { params => { password => 'my password', length => 128, function => 'SHA512', iterations => '1000'  },
     expecterror => '',
     hashlength  => 214, name => 'L 128 F SHA512 I 1000' },
    
) {
    my $thash = $h->create_pbkdf2_password_hash(%{ $testplan->{params} });
    is( $h->errorstring, $testplan->{expecterror}, $testplan->{name} . ' error string' );
    is( length($thash), $testplan->{hashlength}, $testplan->{name} . ' hash length');
}

done_testing;
