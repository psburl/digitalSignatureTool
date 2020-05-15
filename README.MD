# Digital Signature Tool

This project implements 3 digital signature functions, the list of tools are listed below:

* genkey: Generates assimetric keys and stores them on current path in a folder called `keys`
* sign: signs the specified file (argument -i) and saves the output on a folder called `signed-messages`
* verify: verifies the authenticity of a signature of a signed message using the public key


### How do I get set up? ###

To run this project locally, first of all you need to clone this repository, the project had the following requirements: 

#### Requirements ####

* docker
* docker-compose

To run the project you just need to execute `execute.sh` file passing required arguments. The possible arguments are listed below:

* f: specifies wich function shuold be executed. Possible values are: [genkey, sign, verify];
* i: specifies the path of input message, required on `sign` and `verify` funcitons; 
* k: specifies the path of key (pem file) to be used by function, required on `sign` and `verify` funcitons;

### Examples of use ###

The following command generates public and private key files and stores them on a folder called `keys`

```sh
./execute -f genkeys
```

The following command signs `README.md` file using the private key stored on path  `keys/private.pem`

```sh
./execute.sh -f sign -i README.MD -k keys/private.pem
```

The following command verifies the authenticity of `signed-messages/message.signed` file signature using the public key stored in `keys/public.pem`

```sh
./execute.sh -f verify -i signed-messages/message.signed -k keys/public.pem
```