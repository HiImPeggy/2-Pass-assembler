#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define max 17
FILE *finptr;
int oplen = 0;		//lines of opcode
int sourcelen = 0;	//lines of source
int symcount = 0;

struct symbol{
	char name[max];
	int address;
};

struct opcode{
	char mnemonic[max];
	int operandcode;
};

struct source{
	int loc;
	char label[max];
	char operater[max];
	char operand[max];
	char objectcode[max];
};

void pass2(struct source *source, struct symbol *symbtable){
	/*read opcode*/
	char tmp[max], c;
	int i = 0, j = 0, k = 0;
	
	finptr = fopen("opcode.txt","r");
	if(!finptr){
		printf("failed to open");
	}
	while(!feof(finptr)){
		fscanf(finptr,"%[^\n]",tmp);	//read a line and store content in tmp
		//printf("%s\n",tmp);	
		fscanf(finptr,"\n");
		oplen++;
	}
	//printf("%d\n",oplen);
	struct opcode optable[oplen];	//set the size of opcode table
	
	/*initialize*/
	for (i = 0; i < oplen; i++)
    {
        optable[i] = (struct opcode){"", 0};
    }
	
	rewind(finptr);	//back to begin of file
	
	int count = 0;
	
    while(!feof(finptr)){
    	fscanf(finptr,"%s %X ",&optable[count].mnemonic,&optable[count].operandcode);
    	//printf("%s %X\n",optable[count].mnemonic,optable[count].operandcode);
    	count++;
	}
	close(finptr);
	
	char store[max];
	int  index = 0, flag = 0;
	
	for(i = 1; strcmp(source[i].operater, "END") != 0; i++){
		memset(store,'\0',max);
		memset(tmp,'\0',max);
		flag = 0;
		
		for (j = 0; j < oplen; j++) // search OPTAB for OPCODE
        {
            if (strcmp(source[i].operater, optable[j].mnemonic) == 0) // if found
            {
                sprintf(source[i].objectcode, "%02X", optable[j].operandcode); // store the opcode of operation
                //printf("%s\n",source[i].objectcode);
            }
        } // search OPTAB for OPCODE
        
        if(strcmp(source[i].operater,"RESW") == 0 || strcmp(source[i].operater,"RESB") == 0){
			//printf("%X\t%s\t%s\t%s\t%s\n",source[i].loc,source[i].label,source[i].operater,source[i].operand,source[i].objectcode);
			continue;
		}
		else if(strcmp(source[i].operater,"RSUB") == 0){
			strcat(source[i].objectcode,"0000");
		}
		else if(strcmp(source[i].operater,"WORD") == 0){
			sprintf(source[i].objectcode,"%06X",atoi(source[i].operand));
		}
		else if(strcmp(source[i].operater,"BYTE") == 0){
			if(source[i].operand[0] == 'C'){
				for (k = 2; source[i].operand[k] != '\''; k++) // copy the char to tmp
                {
                    /* copy the hex number of the char to the string */
                    sprintf(store, "%X", source[i].operand[k]);
                    strcat(source[i].objectcode, store);
                }
			}
			else if(source[i].operand[0] == 'X'){	//case X
				for (k = 2; source[i].operand[k] != '\''; k++){
					store[index++] = source[i].operand[k];
				}
				strcat(source[i].objectcode, store);
				index = 0;
			}
		}
		else{	//normal case 
			for(j = 0; j < symcount; j++){	
				int len = strlen(symbtable[j].name);
				
                if (strcmp(source[i].operand, symbtable[j].name) == 0) // if found
                {	sprintf(store, "%04X", symbtable[j].address); // translate the hex value into string
                    strcat(source[i].objectcode, store);
                    flag = 1;
             	}
			}
			
			
			if(flag==0){	//case "BUFFER,X"
				//printf("hi");
				for(j = 0; source[i].operand[j] != ','; j++){
					tmp[j] = source[i].operand[j];
					//printf("%c",tmp[j]);
				}
				
				for(j = 0; j < symcount; j++){	//find symbol 
					int len = strlen(symbtable[j].name);
					
	                if (strncmp(source[i].operand, symbtable[j].name,len) == 0) // if found
	                {	//printf("%s\n",source[i].operand);
	                	int add = symbtable[j].address + 0X8000;
	                	//printf("%x %x",symbtable[j].address,add);
						sprintf(store, "%04X", add);
	                	strcat(source[i].objectcode,store);
	             	}
				}
			/**/	
			}
			
		}
       	//printf("%X\t%s\t%s\t%s\t%s\n",source[i].loc,source[i].label,source[i].operater,source[i].operand,source[i].objectcode)
	}
	
	FILE *fout, *fout2;
	fout = fopen("sourceProgram.txt","w");
	fprintf(fout,"Loc\t\tSource Statment\t\tObject Code\n\n");
	
	for(i = 0; i < sourcelen - 1; i++){
		
        fprintf(fout, "%X\t", source[i].loc);
        fprintf(fout, "%s\t", source[i].label);
        fprintf(fout, "%s\t", source[i].operater);
        fprintf(fout, "%s\t\t", source[i].operand);
        fprintf(fout, "%s\n", source[i].objectcode);
    }
    fprintf(fout, "\t%s\t", source[sourcelen - 1].label);
    fprintf(fout, "%s\t", source[sourcelen - 1].operater);
    fprintf(fout, "%s\t", source[sourcelen - 1].operand);
    fprintf(fout, "%s\n", source[sourcelen - 1].objectcode);
	fclose(fout);
	
	/*object code*/
	fout2 = fopen("Objectprogram.txt","w");
	fprintf(fout2,"H%s\t%06X%06X\n", source[0].label,source[0].loc, (source[sourcelen-1].loc-source[0].loc) );
	
	int cnt = 1, track = 0 , pre = 1, record = 0, len = 0;	
	// track to trace not > 10, cnt to know where is the location now, pre is the previous loction
	char obj[60];
	
	while(strcmp(source[cnt].operater,"END")!=0){
		memset(obj,'\0',60);
		track = 0;	pre = cnt;	flag = 0;	
		fprintf(fout2,"T%06X",source[pre].loc+(source[cnt].loc-source[pre].loc) );
		
		for(i = cnt; track != 10 && strcmp(source[cnt].operater,"END") != 0; i++){
			if(strcmp(source[i].operater,"RESW") == 0 || strcmp(source[i].operater,"RESB") == 0){
				if(!flag){
					record = cnt;	// record to save the location of special case
					flag = 1;
				}	
				//printf("%06X",obj);
			}
			else{
				//printf("%s",source[i].objectcode);
				strcat(obj,source[i].objectcode);		
			}
			cnt++;
			track++;
		}
		
		if(!flag){	//not special case
			//printf("%02X", (source[cnt].loc-source[pre].loc) );	
			fprintf(fout2,"%02X", (source[cnt].loc-source[pre].loc));
		}
		else{	//specail case
			//printf("%02X", (source[record].loc-source[pre].loc) );
			fprintf(fout2,"%02X", (source[record].loc-source[pre].loc));	
		}
		//printf("%s",obj);
		fprintf(fout2,"%s",obj);
		//printf("\n");
		fprintf(fout2,"\n");
	}
	
	fprintf(fout2,"E%06X\n", source[0].loc);
		
	fclose(fout2);
}

void pass1(struct source *source, struct symbol *symbtable){
	FILE *foutptr1, *foutptr;
	int i = 0, j = 0, location = 0;//symbol table
	
    source[0].loc = strtol(source[0].operand, NULL, 16); // string to hex(16 is base)
	location = source[0].loc;
	
    for(i = 1; i < sourcelen && strcmp(source[i].operater, "END") != 0 ; i++){
    	source[i].loc = location;
    	
    	/*insert in symbol table*/
    	if (strcmp(source[i].label, "") != 0) // symbol exist
        {   strcpy(symbtable[symcount].name, source[i].label);
            symbtable[symcount].address = location;
            symcount++;
        } 

        /*count locctr*/
		if (strcmp(source[i].operater, "RESW") == 0) 
        {
            location += 3 * strtol(source[i].operand, NULL, 10);
        }
        else if (strcmp(source[i].operater, "RESB") == 0) 
        {
            location += strtol(source[i].operand, NULL, 10);
        }
        else if (strcmp(source[i].operater, "BYTE") == 0) 
        {
            if (source[i].operand[0] == 'X' || source[i].operand[0] == 'X'){
                location += (strlen(source[i].operand) - 3) / 2;
            }
            else // char
            {
                location += strlen(source[i].operand) - 3; //
            }
        }
        else{
        	location += 3;
		}
		//printf("%X\t%s\t%s\t%s\n",source[i].loc,source[i].label,source[i].operater,source[i].operand);
	}
	source[sourcelen - 1].loc = location;
	
	foutptr = fopen("SymbolTabel.txt","w");
	foutptr1 = fopen("Pass1_program.txt","w");
	
	pass2(source,symbtable);
	
	/*output symbol table*/
	//printf("Label Name\tAddress\n");
	fprintf(foutptr,"Label Name\tAddress\n");
	for(i = 0; i < symcount; i++){
		//printf("%s\t%12X\n",symbtable[i].name,symbtable[i].address);
		fprintf(foutptr,"%s\t%12X\n",symbtable[i].name,symbtable[i].address); 
	}
	
	/*output pass1 program*/
	fprintf(foutptr1,"Loc\t\tSource statment\n\n");
	for (i = 0; i < sourcelen - 1; i++)
    {
        fprintf(foutptr1, "%X\t", source[i].loc);
        fprintf(foutptr1, "%s\t", source[i].label);
        fprintf(foutptr1, "%s\t", source[i].operater);
        fprintf(foutptr1, "%s\n", source[i].operand);
    }
    //last one 
    fprintf(foutptr1, "\t%s\t", source[sourcelen - 1].label);
    fprintf(foutptr1, "%s\t", source[sourcelen - 1].operater);
    fprintf(foutptr1, "%s\n", source[sourcelen - 1].operand);
    
	fclose(foutptr);
	fclose(foutptr1);
}

void sourcecode(){
	char tmp[50],name[50],c='\0';
	int t;
	
	/*read source file*/
	finptr = fopen("source.txt","r");
	if(!finptr){
		printf("failed to open");
	}
	while(!feof(finptr)){
		fscanf(finptr,"%[^\n]",tmp);	//read a line and store content in tmp
		//printf("%s\n",tmp);	
		fscanf(finptr,"\n");
		sourcelen++;
	}
	//printf("%d\n",sourcelen);
	struct source source[sourcelen];
	struct symbol symbtable[sourcelen];
	
	/*initialize*/
	for(t = 0; t < sourcelen; t++){
		source[t] = (struct source){0, "", "", "", ""};
		symbtable[t] = (struct symbol){"",0};
	}
	
	rewind(finptr);
	
	int i = 0, j = 0;
	while(!feof(finptr)){
		/*lable*/
		for (j = 0; (c = fgetc(finptr)) != '\t'; j++) 
        {	if (c == ' ')	continue;
            source[i].label[j] = c;
        }
        
        /*operater*/
        for (j = 0; ((c = fgetc(finptr)) != '\n' && c != '\t'); j++) 
        {	if (c == ' ')	continue;
            source[i].operater[j] = c;
        }
        
        if (c == '\n')
        {	//printf("%s\n",source[i].operater);
        	i++;
            continue;
        }
        
        //printf("%s\t",source[i].operater);
        
        /*operand*/
        for (j = 0; (c = fgetc(finptr)) != '\n'; j++) 
        {	
        	if(c == EOF)	break;
        	else if (c == ' ')	continue;
            source[i].operand[j] = c;
        }
        //printf("%s\n",source[i].operand);
        i++;
	}
	
	pass1(source,symbtable);
	
	close(finptr);
}


int main(){

	sourcecode();

	return 0;
} 
