int main(int argc, char **argv) {
	if (argc == 2) {

		seed_string=input[1];
		seed_string_len=strlen(input[1])+1;
		second_seed=0LL;

		while (seed_string != &input[seed_string_len-1]) {
			a=*seed_string++;
			second_seed^=a;
		}

		memset(arr_0x400a40ay,0,0x100uLL);
		b1=16631*second_seed+511115;
		c1=arr_0x400a40_0x400a40[b1 % 0x7fffffff % 0x82];
		b2=16631*(b1 % 0x7fffffff)+511115;
		c2=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b3=16631*(b1 % 0x7fffffff)+511115;
		c2=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b4=16631*(b1 % 0x7fffffff)+511115;
		c3=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b5=16631*(b1 % 0x7fffffff)+511115;
		c4=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b6=16631*(b1 % 0x7fffffff)+511115;
		c5=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b7=16631*(b1 % 0x7fffffff)+511115;
		c6=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b8=16631*(b1 % 0x7fffffff)+511115;
		c7=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b9=16631*(b1 % 0x7fffffff)+511115;
		c8=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b10=16631*(b1 % 0x7fffffff)+511115;
		c9=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b11=16631*(b1 % 0x7fffffff)+511115;
		c10=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b12=16631*(b1 % 0x7fffffff)+511115;
		c10=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b13=16631*(b1 % 0x7fffffff)+511115;
		c11=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b14=16631*(b1 % 0x7fffffff)+511115;
		c12=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b15=16631*(b1 % 0x7fffffff)+511115;
		c13=arr_0x400a40[b1 % 0x7fffffff % 0x82];
		b16=16631*(b1 % 0x7fffffff)+511115;
		c14=arr_0x400a40[b16 % 0x7fffffff % 0x82];
		c15=arr_0x400a40[b16 % 0x7fffffff % 0x82];
		puts(arr_0x400a40a);

		return 0;
}
