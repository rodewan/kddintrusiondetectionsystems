%{
Rohit Dewan
%}

%{
for the very first task, the large scale SVM classifer comprising the LIBLINEAR
 library, developed by Prof. Chih-Jen Lin and his Machine Learning Group at
 National Taiwan University, obtained from https://wwww.csie.ntu.edu.tw/~cjlin/liblinear/ 
is installed.  

In particular, becuase the platform used was an i64 Mac (my OS platform), 
the files for the large scale multi-class SVM classifier are built separately by 
compiling the '.c' and '.cpp' files present by running the make.m file.
For that reason, this file MUST be run in the 'matlab' folder of the
extracted 'liblinear' folder, and using 'mex -setup' in MATLAB a compiler must be pre-selected.
In my case, before running this file, first the OS compiler was selected by using the 'mex -setup' command in
MATLAB.  I preset the mex compiler to use the 'XCode with Clang'
compiler for the C files and 'XCode with Clang++' for the C++ files.en units respectively
%}
%make;
%now we have built the 'train', 'predict', 'libsvmread', and 'libsvmwrite'
%commands for MATLAB

%{
for the second task, the KDD cup data is pre-processed before the
large-scale mult-class SVM classifier can be run.  In particular, as per
the preprocessing guide specified by
(http://www.csie.ntu.edu.tw/~cjlin/papers/guide/guide.pdf), the first step
is to represent categorical data using m numbers for a m-category
attribute, e.g. {red, green, blue} = (0,0,1), (0,1,0), and (1,0,0)
respectively.  Secondly, all continuous data needs to be normalized on the
[0,1] scale.  The reason both these steps occur is to not create artificial
distance (in the first case, between any two colors compared to the other
color, and in the second case by having values out of proportion affect the
classifier disproportionately - we want to give equal weight to the
features even if they are on different scales).  So we load the KDD cup
data file, which has 41 features.
%}

fileID = fopen('kddcup.data_10_percent');
writeID = fopen('kddcupaltered','wt');
i=1;
tline = fgetl(fileID);
A=tline;
while ischar(tline)
    C=strsplit(A,',');
    if strcmp(C{1,2},'tcp')
        C{1,2} = '1,0,0';
    elseif strcmp(C{1,2},'udp')
        C{1,2} = '0,1,0';
    elseif strcmp(C{1,2},'icmp')
        C{1,2}= '0,0,1';
    else
        fprintf('there was some error in processing the protocol type\n');
    end
    if strcmp(C{1,3},'http')
        C{1,3} = '1,0,0,0,0';
    elseif strcmp(C{1,3},'ftp')
        C{1,3} = '0,1,0,0,0';
    elseif strcmp(C{1,3},'smtp')
        C{1,3}= '0,0,1,0,0';
    elseif strcmp(C{1,3},'telnet')
        C{1,3}='0,0,0,1,0';
    else
        C{1,3}='0,0,0,0,1';
    end
    if strcmp(C{1,4},'SF')
        C{1,4} = '1,0,0,0,0,0,0,0,0,0,0,0';
    elseif strcmp(C{1,4},'S0')
        C{1,4} = '0,1,0,0,0,0,0,0,0,0,0,0';
    elseif strcmp(C{1,4},'S1')
        C{1,4}= '0,0,1,0,0,0,0,0,0,0,0,0';
    elseif strcmp(C{1,4},'S2')
        C{1,4}= '0,0,0,1,0,0,0,0,0,0,0,0';
    elseif strcmp(C{1,4},'S3')
        C{1,4}= '0,0,0,0,1,0,0,0,0,0,0,0';
    elseif strcmp(C{1,4},'OTH')
        C{1,4}= '0,0,0,0,0,1,0,0,0,0,0,0';
    elseif strcmp(C{1,4},'REJ')
        C{1,4}= '0,0,0,0,0,0,1,0,0,0,0,0';
    elseif strcmp(C{1,4},'RSTO')
        C{1,4}= '0,0,0,0,0,0,0,1,0,0,0,0';
    elseif strcmp(C{1,4},'RSTOS0')
        C{1,4}= '0,0,0,0,0,0,0,0,1,0,0,0';
    elseif strcmp(C{1,4},'SH')
        C{1,4}= '0,0,0,0,0,0,0,0,0,1,0,0';
    elseif strcmp(C{1,4},'RSTR')
        C{1,4}= '0,0,0,0,0,0,0,0,0,0,1,0';
    elseif strcmp(C{1,4},'SHR')
        C{1,4}= '0,0,0,0,0,0,0,0,0,0,0,1';        
    else
        disp(sprintf('Flag is %s',C{1,4}));
    end
    if strcmp(C{1,42},'portsweep.') | strcmp(C{1,42},'ipsweep.') | strcmp(C{1,42},'queso.') | strcmp(C{1,42},'satan.') | strcmp(C{1,42},'msscan.') | strcmp(C{1,42},'ntinfoscan.') | strcmp(C{1,42},'lsdomain.') | strcmp(C{1,42},'illegal-sniffer.')|strcmp(C{1,42},'nmap.')
        C{1,42} = '5'; %this is a probe type attack
    elseif strcmp(C{1,42},'apache2.')|strcmp(C{1,42},'smurf.')|strcmp(C{1,42},'neptune.')|strcmp(C{1,42},'dosnuke.')|strcmp(C{1,42},'land.')|strcmp(C{1,42},'pod.')|strcmp(C{1,42},'back.')|strcmp(C{1,42},'teardrop.')|strcmp(C{1,42},'tcpreset.')|strcmp(C{1,42},'syslogd.')|strcmp(C{1,42},'crashiis.')|strcmp(C{1,42},'arppoison.')|strcmp(C{1,42},'mailbomb.')|strcmp(C{1,42},'selfping.')|strcmp(C{1,42},'processtable.')|strcmp(C{1,42},'udpstorm.')
        C{1,42} = '4'; %this is a denial of service type attack
    elseif strcmp(C{1,42},'diet.')|strcmp(C{1,42},'multihop.')|strcmp(C{1,42},'netcat.')|strcmp(C{1,42},'sendmail.')|strcmp(C{1,42},'imap.')|strcmp(C{1,42},'ncftp.')|strcmp(C{1,42},'xlock.')|strcmp(C{1,42},'xsnoop.')|strcmp(C{1,42},'sshtrojan.')|strcmp(C{1,42},'framespoof.')|strcmp(C{1,42},'ppmacro.')|strcmp(C{1,42},'guest.')|strcmp(C{1,42},'netbus.')|strcmp(C{1,42},'snmpget.')|strcmp(C{1,42},'ftp_write.')|strcmp(C{1,42},'httptunnel.')|strcmp(C{1,42},'phf.')|strcmp(C{1,42},'named.')|strcmp(C{1,42},'guess_passwd.')|strcmp(C{1,42},'warezclient.')|strcmp(C{1,42},'warezmaster.')|strcmp(C{1,42},'spy.')
        C{1,42}= '3'; %this is a R2L type attack
    elseif strcmp(C{1,42},'sechole.')|strcmp(C{1,42},'rootkit.')|strcmp(C{1,42},'xterm.')|strcmp(C{1,42},'eject.')|strcmp(C{1,42},'ps.')|strcmp(C{1,42},'nukepw.')|strcmp(C{1,42},'secret.')|strcmp(C{1,42},'perl.')|strcmp(C{1,42},'yaga.')|strcmp(C{1,42},'fdformat.')|strcmp(C{1,42},'ffbconfig.')|strcmp(C{1,42},'casesen.')|strcmp(C{1,42},'ntfsdos.')|strcmp(C{1,42},'ppmacro.')|strcmp(C{1,42},'loadmodule.')|strcmp(C{1,42},'sqlattack.')|strcmp(C{1,42},'buffer_overflow.')
        C{1,42}='2'; %this is a U2R type attack
    elseif strcmp(C{1,42},'normal.')
        C{1,42}='1';   
    else 
         disp(sprintf('Could not detect attack type%s',C{1,42}));
    end
    allOneString = sprintf('%s,',C{:});
    allOneString = allOneString(1:end-1);
    fprintf(writeID, '%s\n',allOneString);
    i=i+1;
    tline=fgetl(fileID);
    if tline~=-1
        A=tline;
    end  
end
fclose(fileID);
fclose(writeID);
newtable = csvread('kddcupaltered');
for x=1:length(newtable(1,:))-1
    tempmax = max(newtable(:,x));
    tempmin = min(newtable(:,x));
    for y=1:length(newtable(:,1))
        if tempmax-tempmin~=0
                   newtable(y,x)= (newtable(y,x)-tempmin)/(tempmax-tempmin);
        end    
    end
end
%the following code snippet is uncommented when we want to make sure all
%columns are properly normalized
%for z=1:length(newtable(1,:))
%            disp(sprintf('column%d has max of %d',z,max(newtable(:,z))));
%end

%this next code section is very important as it
%assigns the last column of the table to the labels variable
%and the first through (last-1) columns to features, and converts
%the features to a sparse array
%then this can be used by the LIBLINEAR library to develop a L2 regularized
%training model
labels = newtable(:,length(newtable(1,:)));
features = newtable(:,1:(length(newtable(1,:))-1));
features_sparse=sparse(features);
model=train(labels,features_sparse);
%we set one model with a bias and one without one to compare if our data is
%centered/normalized correctly
fprintf('KDD99 Set Statistics are as follows:');
model1=train(labels,features_sparse,'-B 1');
fprintf('Statistics for training using the KDD 99 training set (unbiased) and then testing on the same training set:\n '); 
[predicted_label, accuracy,prob_estimates] = predict(labels, features_sparse, model);
fprintf('Statistics for training using the KDD 99 training set (biased) and then testing on the same training set:\n '); 
[predicted_label1, accuracy1,prob_estimates1] = predict(labels, features_sparse, model1);
%we next process the training data
fileID = fopen('corrected');
writeID = fopen('newcorrected','wt');
i=1;
tline = fgetl(fileID);
A=tline;
while ischar(tline)
    C=strsplit(A,',');
    if strcmp(C{1,2},'tcp')
        C{1,2} = '1,0,0';
    elseif strcmp(C{1,2},'udp')
        C{1,2} = '0,1,0';
    elseif strcmp(C{1,2},'icmp')
        C{1,2}= '0,0,1';
    else
        fprintf('there was some error in processing the protocol type\n');
    end
    if strcmp(C{1,3},'http')
        C{1,3} = '1,0,0,0,0';
    elseif strcmp(C{1,3},'ftp')
        C{1,3} = '0,1,0,0,0';
    elseif strcmp(C{1,3},'smtp')
        C{1,3}= '0,0,1,0,0';
    elseif strcmp(C{1,3},'telnet')
        C{1,3}='0,0,0,1,0';
    else
        C{1,3}='0,0,0,0,1';
    end
    if strcmp(C{1,4},'SF')
        C{1,4} = '1,0,0,0,0,0,0,0,0,0,0,0';
    elseif strcmp(C{1,4},'S0')
        C{1,4} = '0,1,0,0,0,0,0,0,0,0,0,0';
    elseif strcmp(C{1,4},'S1')
        C{1,4}= '0,0,1,0,0,0,0,0,0,0,0,0';
    elseif strcmp(C{1,4},'S2')
        C{1,4}= '0,0,0,1,0,0,0,0,0,0,0,0';
    elseif strcmp(C{1,4},'S3')
        C{1,4}= '0,0,0,0,1,0,0,0,0,0,0,0';
    elseif strcmp(C{1,4},'OTH')
        C{1,4}= '0,0,0,0,0,1,0,0,0,0,0,0';
    elseif strcmp(C{1,4},'REJ')
        C{1,4}= '0,0,0,0,0,0,1,0,0,0,0,0';
    elseif strcmp(C{1,4},'RSTO')
        C{1,4}= '0,0,0,0,0,0,0,1,0,0,0,0';
    elseif strcmp(C{1,4},'RSTOS0')
        C{1,4}= '0,0,0,0,0,0,0,0,1,0,0,0';
    elseif strcmp(C{1,4},'SH')
        C{1,4}= '0,0,0,0,0,0,0,0,0,1,0,0';
    elseif strcmp(C{1,4},'RSTR')
        C{1,4}= '0,0,0,0,0,0,0,0,0,0,1,0';
    elseif strcmp(C{1,4},'SHR')
        C{1,4}= '0,0,0,0,0,0,0,0,0,0,0,1';        
    else
        disp(sprintf('Flag is %s',C{1,4}));
    end
    if strcmp(C{1,42},'portsweep.') | strcmp(C{1,42},'saint.') |strcmp(C{1,42},'mscan.') |strcmp(C{1,42},'ipsweep.') | strcmp(C{1,42},'queso.') | strcmp(C{1,42},'satan.') | strcmp(C{1,42},'msscan.') | strcmp(C{1,42},'ntinfoscan.') | strcmp(C{1,42},'lsdomain.') | strcmp(C{1,42},'illegal-sniffer.')|strcmp(C{1,42},'nmap.')
        C{1,42} = '5'; %this is a probe type attack
    elseif strcmp(C{1,42},'apache2.')|strcmp(C{1,42},'smurf.')|strcmp(C{1,42},'neptune.')|strcmp(C{1,42},'dosnuke.')|strcmp(C{1,42},'land.')|strcmp(C{1,42},'pod.')|strcmp(C{1,42},'back.')|strcmp(C{1,42},'teardrop.')|strcmp(C{1,42},'tcpreset.')|strcmp(C{1,42},'syslogd.')|strcmp(C{1,42},'crashiis.')|strcmp(C{1,42},'arppoison.')|strcmp(C{1,42},'mailbomb.')|strcmp(C{1,42},'selfping.')|strcmp(C{1,42},'processtable.')|strcmp(C{1,42},'udpstorm.')
        C{1,42} = '4'; %this is a denial of service type attack
    elseif strcmp(C{1,42},'diet.')|strcmp(C{1,42},'snmpguess.')|strcmp(C{1,42},'snmpgetattack.')|strcmp(C{1,42},'multihop.')|strcmp(C{1,42},'netcat.')|strcmp(C{1,42},'sendmail.')|strcmp(C{1,42},'imap.')|strcmp(C{1,42},'ncftp.')|strcmp(C{1,42},'xlock.')|strcmp(C{1,42},'xsnoop.')|strcmp(C{1,42},'sshtrojan.')|strcmp(C{1,42},'framespoof.')|strcmp(C{1,42},'ppmacro.')|strcmp(C{1,42},'guest.')|strcmp(C{1,42},'netbus.')|strcmp(C{1,42},'snmpget.')|strcmp(C{1,42},'ftp_write.')|strcmp(C{1,42},'httptunnel.')|strcmp(C{1,42},'phf.')|strcmp(C{1,42},'named.')|strcmp(C{1,42},'guess_passwd.')|strcmp(C{1,42},'warezclient.')|strcmp(C{1,42},'warezmaster.')|strcmp(C{1,42},'spy.')|strcmp(C{1,42},'worm.')
        C{1,42}= '3'; %this is a R2L type attack
    elseif strcmp(C{1,42},'sechole.')|strcmp(C{1,42},'rootkit.')|strcmp(C{1,42},'xterm.')|strcmp(C{1,42},'eject.')|strcmp(C{1,42},'ps.')|strcmp(C{1,42},'nukepw.')|strcmp(C{1,42},'secret.')|strcmp(C{1,42},'perl.')|strcmp(C{1,42},'yaga.')|strcmp(C{1,42},'fdformat.')|strcmp(C{1,42},'ffbconfig.')|strcmp(C{1,42},'casesen.')|strcmp(C{1,42},'ntfsdos.')|strcmp(C{1,42},'ppmacro.')|strcmp(C{1,42},'loadmodule.')|strcmp(C{1,42},'sqlattack.')|strcmp(C{1,42},'buffer_overflow.')
        C{1,42}='2'; %this is a U2R type attack
    elseif strcmp(C{1,42},'normal.')
        C{1,42}='1';   
    else 
         disp(sprintf('Could not detect attack type%s',C{1,42}));
    end
    allOneString = sprintf('%s,',C{:});
    allOneString = allOneString(1:end-1);
    fprintf(writeID, '%s\n',allOneString);
    i=i+1;
    tline=fgetl(fileID);
    if tline~=-1
        A=tline;
    end  
end
fclose(fileID);
fclose(writeID);
newtable = csvread('newcorrected');
for x=1:length(newtable(1,:))-1
    tempmax = max(newtable(:,x));
    tempmin = min(newtable(:,x));
    for y=1:length(newtable(:,1))
        if tempmax-tempmin~=0
                   newtable(y,x)= (newtable(y,x)-tempmin)/(tempmax-tempmin);
        end    
    end
end

%the following code snippet is uncommented when we want to make sure all
%columns are properly normalized
%for z=1:length(newtable(1,:))
%            disp(sprintf('column%d has max of %d',z,max(newtable(:,z))));
%end

%this next code section is very important as it
%assigns the last column of the table to the labels variable
%and the first through (last-1) columns to features, and converts
%the features to a sparse array
%then this can be used by the LIBLINEAR library to develop a L2 regularized
%training model
labels = newtable(:,length(newtable(1,:)));
features = newtable(:,1:(length(newtable(1,:))-1));
features_sparse = sparse(features);
fprintf('Statistics for testing using the previously trained model (unbiased) on the KDD 99 testing data: ');
[predicted_label, accuracy,prob_estimates] = predict(labels, features_sparse, model);
fprintf('Statistics for testing using the previously trained model (biased) on the KDD 99 testing data: ');
[predicted_label1, accuracy1,prob_estimates1] = predict(labels, features_sparse, model1);
