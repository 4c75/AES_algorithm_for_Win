//this is also nice:
//https://www.lri.fr/~fmartignon/documenti/systemesecurite/5-AES.pdf

//Shit taken from here:
//https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

//TODO - Rijnadaels key schedule?

static unsigned char Rijndael_S_box[256] =
 {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
 };


void AddRoundKey(char *state, char *round_key)
{
    for(int i=0; i < 16; i++)
	{
        state[i] = state [i] ^ round_key[i];
	};
};

// pass array of 16 elements
/*We swap char with it's S-Box value
(The first 4 bits in the byte (the first hexadecimal value, hence) individuate the row,
the last 4 bits individuate the column) in Rijndael S-Box*/
void SubBtyes(char *state)
{
    int i = 0, j = 0;
    for(; i<4; i++)
	{
        for(; j<4; j++)
		{
            unsigned char first_4_bits = state[i*4 +j] >> 4; //shift all bits 4 indexes to right;
            unsigned char last_4_bits = state[i*4 +j] & 0x0f; //logical and with 00001111;
            state[i*4 +j] = Rijndael_S_box[first_4_bits * 16 + last_4_bits]; //means [first_4_bits][last_4_bits]
		};
	};
    /*			//do we need this part of code?
	for(int i=0; i<4; i++)
	{
       for(int j=0; j<4; j++)
	   {
            state[i][j] = lookup[i][j]; // or make S function
        };
    }*/
};

// pass array of 16 elements
void ShiftRows(char *state)
{
    int row = 1, col = 1;
    for(; row<4; row++)
	{
        char remember = state[row *4+ 0];
        for(1; col<4; col++){
            state[row *4+ (col-1)] = state[row *4+ col];
		};
		state[row*4 + 3] = remember;
	};
};

void ShiftRows_inversed(char *state)
{
	int row = 1, col = 2;
	for (; row<4; row++)
	{
		char remember = state[row * 4 + 3];
		for (; col<1; col--){
			state[row * 4 + (col + 1)] = state[row * 4 + col];
		};
		state[row * 4 + 0] = remember;
	};
};


/*
0E 0B 0D 09
09 0E 0B 0D
0D 09 0E 0B
0B 0D 09 0E
*/
void MixColumns(char *state)  
{
	for (int i = 0; i < 16; i=i+4)
	{
		state[i] = 2 * state[i] + 3 * state[i + 1] + state[i + 2] + state[i + 3];
		state[i+1]= 1 * state[i] + 2 * state[i + 1] + 3 * state[i + 2] + state[i + 3];
		state[i+2]= 1 * state[i] + 1 * state[i + 1] + 2 * state[i + 2] + 3 * state[i + 3];
		state[i+3]= 3 * state[i] + 1 * state[i + 1] + state[i + 2] + 2 * state[i + 3];
	};
};

void MixColumns_inversed(char *state)//work in progress
{
	for (int i = 0; i < 16; i = i + 4)
	{
		state[i] = 1;
		state[i + 1] = 1;
		state[i + 2] = 1;
		state[i + 3] = 1;
	};
};

void Rot_Word(char* word)
{
	char temp[2];
	temp[0] = word[0];
	word[0] = word[1];
	word[1] = word[2];
	word[2] = word[3];
	word[3] = temp[0];
};

void XOR_column(char* prew_key, char* key, int column)
{
	//need to add another table, which will be added as another xor?   Rcon?
	//10x4   use 1 column in each round key (first round, first column...)
	
	switch (column)
	{
	case 1:					//Need to add xor part of rot_column on in this case
		key[0] = prew_key[0] ^ key[0];
		key[1] = prew_key[1] ^ key[1];
		key[2] = prew_key[2] ^ key[2];
		key[3] = prew_key[3] ^ key[3];
	case 2:
		key[4] = prew_key[4] ^ key[0];
		key[5] = prew_key[5] ^ key[1];
		key[6] = prew_key[6] ^ key[2];
		key[7] = prew_key[7] ^ key[3];
	case 3:
		key[8] = prew_key[8] ^ key[4];
		key[9] = prew_key[9] ^ key[5];
		key[10] = prew_key[10] ^ key[6];
		key[11] = prew_key[11] ^ key[7];
	case 4:
		key[12] = prew_key[12] ^ key[8];
		key[13] = prew_key[13] ^ key[9];
		key[14] = prew_key[14] ^ key[10];
		key[15] = prew_key[15] ^ key[12];
	}
};

void getRoundKey(char *key, char* round_key)
{
	char temp[]="1234";
	//Take 4 elements from first key (last column)
	temp[0] = key[11]; 
	temp[1] = key[12];
	temp[2] = key[13];
	temp[3] = key[14];
	Rot_Word(temp);  //Rot_word and subbyte and rot_column only for first column
	//subbyte
	XOR_column(key, round_key, 1);
	XOR_column(key, round_key, 2);
	XOR_column(key, round_key, 3);
	XOR_column(key, round_key, 4);
};

void encrypt_AES(char *state, char* key)
{
	char *round_key;
	char *prew_round_key;
	AddRoundKey(state, key);
	prew_round_key = key;
	round_key = key;
	for(int i=0; i<9 ;i++){
        SubBtyes(state); //will need to check
        ShiftRows(state); //will need to check
        MixColumns(state);
		getRoundKey(prew_round_key, round_key);
        AddRoundKey(state, round_key);
		prew_round_key = round_key;
	};
    SubBtyes(state);
    ShiftRows(state);
	getRoundKey(prew_round_key, round_key);
    AddRoundKey(prew_round_key, round_key);
};

void decrypt_AES(char * state, char *key)
{
	char *round_key;
	char *prew_round_key;
	AddRoundKey(state, key);
	prew_round_key = key;
	round_key = key;
	for (int i = 0; i<9; i++) {
		
		ShiftRows_inversed(state); // -> IS_IS correct?  need to make inverse
		SubBtyes(state); //need to make inverse
		getRoundKey(prew_round_key, round_key);
		AddRoundKey(state, round_key);
		MixColumns(state); //inverse
		prew_round_key =round_key;
	};
	ShiftRows_inversed(state);
	SubBtyes(state);//need to make inverse
	getRoundKey(prew_round_key, round_key);
	AddRoundKey(state, round_key);
};

