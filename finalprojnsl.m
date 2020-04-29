%{
Rohit Dewan
%}

%{
for the NSL KDD task, with the NSL KDD data set, we perform the same steps as with the KDD data set,
 except for here we extract the 41 features corresponding to the KDD data set and the labels, and use 
the training set against both the test set (which was developed where the
percentage of samples chosen for the KDD set are inversely proportional to the percentage predicted correctly by groups of learned machines
 per the NSL KDD Paper - groups are 0-5, 6-10, 11-15, 16-20, and 21), and
 also the test-21 set, where records guessed correctly by all 21 learned
 machines in the NSL KDD Paper are EXCLUDED from the dataset. 
Finally, to compare with other training models, a smaller 20% dataset is also used

%}

%{
the NSL KDD cup data is pre-processed in much the same manner as the KDD data before the
large-scale mult-class SVM classifier can be run.  In particular, as per
the preprocessing guide specified by Prof. Lin himself
(http://www.csie.ntu.edu.tw/~cjlin/papers/guide/guide.pdf), the first step
is to represent categorical data using m numbers for a m-category
attribute, e.g. {red, green, blue} = (0,0,1), (0,1,0), and (1,0,0)
respectively.  Secondly, all continuous data needs to be normalized on the
[0,1] scale.  The reason both these steps occur is to not create artificial
distance (in the first case, between any two colors compared to the other
color, and in the second case by having values out of proportion affect the
classifier disproportionately - we want to give equal weight to the
features even if they are on different scales).  So we load the NSLKDD cup
data file, and extract the corresponding 41 features and labels.
%}

fileID = fopen('NSLKDDTrain+_20Percent.txt');
writeID = fopen('NSLKDDTrainAltered','wt');
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
    %Note there is no period in the NSL KDD data file so our parsing for
    %the attack type must change accordingly, also snmpget is now called
    %snmpgetattack
    if strcmp(C{1,42},'portsweep') | strcmp(C{1,42},'saint') |strcmp(C{1,42},'ipsweep') | strcmp(C{1,42},'queso') | strcmp(C{1,42},'satan') | strcmp(C{1,42},'mscan') | strcmp(C{1,42},'ntinfoscan') | strcmp(C{1,42},'lsdomain') | strcmp(C{1,42},'illegal-sniffer')|strcmp(C{1,42},'nmap')
        C{1,42} = '5'; %this is a probe type attack
    elseif strcmp(C{1,42},'apache2')|strcmp(C{1,42},'smurf')|strcmp(C{1,42},'neptune')|strcmp(C{1,42},'dosnuke')|strcmp(C{1,42},'land')|strcmp(C{1,42},'pod')|strcmp(C{1,42},'back')|strcmp(C{1,42},'teardrop')|strcmp(C{1,42},'tcpreset')|strcmp(C{1,42},'syslogd')|strcmp(C{1,42},'crashiis')|strcmp(C{1,42},'arppoison')|strcmp(C{1,42},'mailbomb')|strcmp(C{1,42},'selfping')|strcmp(C{1,42},'processtable')|strcmp(C{1,42},'udpstorm')
        C{1,42} = '4'; %this is a denial of service type attack
    elseif strcmp(C{1,42},'diet')|strcmp(C{1,42},'worm')|strcmp(C{1,42},'snmpguess')|strcmp(C{1,42},'multihop')|strcmp(C{1,42},'netcat')|strcmp(C{1,42},'sendmail')|strcmp(C{1,42},'imap')|strcmp(C{1,42},'ncftp')|strcmp(C{1,42},'xlock')|strcmp(C{1,42},'xsnoop')|strcmp(C{1,42},'sshtrojan')|strcmp(C{1,42},'framespoof')|strcmp(C{1,42},'ppmacro')|strcmp(C{1,42},'guest')|strcmp(C{1,42},'netbus')|strcmp(C{1,42},'snmpgetattack')|strcmp(C{1,42},'ftp_write')|strcmp(C{1,42},'httptunnel')|strcmp(C{1,42},'phf')|strcmp(C{1,42},'named')|strcmp(C{1,42},'guess_passwd')|strcmp(C{1,42},'warezclient')|strcmp(C{1,42},'warezmaster')|strcmp(C{1,42},'spy')
        C{1,42}= '3'; %this is a R2L type attack
    elseif strcmp(C{1,42},'sechole')|strcmp(C{1,42},'rootkit')|strcmp(C{1,42},'xterm')|strcmp(C{1,42},'eject')|strcmp(C{1,42},'ps')|strcmp(C{1,42},'nukepw')|strcmp(C{1,42},'secret')|strcmp(C{1,42},'perl')|strcmp(C{1,42},'yaga')|strcmp(C{1,42},'fdformat')|strcmp(C{1,42},'ffbconfig')|strcmp(C{1,42},'casesen')|strcmp(C{1,42},'ntfsdos')|strcmp(C{1,42},'ppmacro')|strcmp(C{1,42},'loadmodule')|strcmp(C{1,42},'sqlattack')|strcmp(C{1,42},'buffer_overflow')
        C{1,42}='2'; %this is a U2R type attack
    elseif strcmp(C{1,42},'normal')
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
newtable = csvread('NSLKDDTrainAltered');
for x=1:length(newtable(1,:))-1
    tempmax = max(newtable(:,x));
    tempmin = min(newtable(:,x));
    for y=1:length(newtable(:,1))-1
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
fprintf('NSL-KDD99 Set Statistics are as follows:');
model1=train(labels,features_sparse,'-B 1');
fprintf('Statistics for training using the NSL KDDTest+ 99 training set (unbiased) and then testing on the same training set:\n '); 
[predicted_label, accuracy,prob_estimates] = predict(labels, features_sparse, model);
fprintf('Statistics for training using the KDD KDDTest+ 99 training set (biased) and then testing on the same training set:\n '); 
[predicted_label1, accuracy1,prob_estimates1] = predict(labels, features_sparse, model1);
%we next process the training data for Test+
fileID = fopen('NSLKDDTest+.csv');
writeID = fopen('NSLKDDTestAltered','wt');
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
    if strcmp(C{1,42},'portsweep') | strcmp(C{1,42},'saint') |strcmp(C{1,42},'ipsweep') | strcmp(C{1,42},'queso') | strcmp(C{1,42},'satan') | strcmp(C{1,42},'mscan') | strcmp(C{1,42},'ntinfoscan') | strcmp(C{1,42},'lsdomain') | strcmp(C{1,42},'illegal-sniffer')|strcmp(C{1,42},'nmap')
        C{1,42} = '5'; %this is a probe type attack
    elseif strcmp(C{1,42},'apache2')|strcmp(C{1,42},'smurf')|strcmp(C{1,42},'neptune')|strcmp(C{1,42},'dosnuke')|strcmp(C{1,42},'land')|strcmp(C{1,42},'pod')|strcmp(C{1,42},'back')|strcmp(C{1,42},'teardrop')|strcmp(C{1,42},'tcpreset')|strcmp(C{1,42},'syslogd')|strcmp(C{1,42},'crashiis')|strcmp(C{1,42},'arppoison')|strcmp(C{1,42},'mailbomb')|strcmp(C{1,42},'selfping')|strcmp(C{1,42},'processtable')|strcmp(C{1,42},'udpstorm')
        C{1,42} = '4'; %this is a denial of service type attack
    elseif strcmp(C{1,42},'diet')|strcmp(C{1,42},'worm')|strcmp(C{1,42},'snmpguess')|strcmp(C{1,42},'multihop')|strcmp(C{1,42},'netcat')|strcmp(C{1,42},'sendmail')|strcmp(C{1,42},'imap')|strcmp(C{1,42},'ncftp')|strcmp(C{1,42},'xlock')|strcmp(C{1,42},'xsnoop')|strcmp(C{1,42},'sshtrojan')|strcmp(C{1,42},'framespoof')|strcmp(C{1,42},'ppmacro')|strcmp(C{1,42},'guest')|strcmp(C{1,42},'netbus')|strcmp(C{1,42},'snmpgetattack')|strcmp(C{1,42},'ftp_write')|strcmp(C{1,42},'httptunnel')|strcmp(C{1,42},'phf')|strcmp(C{1,42},'named')|strcmp(C{1,42},'guess_passwd')|strcmp(C{1,42},'warezclient')|strcmp(C{1,42},'warezmaster')|strcmp(C{1,42},'spy')
        C{1,42}= '3'; %this is a R2L type attack
    elseif strcmp(C{1,42},'sechole')|strcmp(C{1,42},'rootkit')|strcmp(C{1,42},'xterm')|strcmp(C{1,42},'eject')|strcmp(C{1,42},'ps')|strcmp(C{1,42},'nukepw')|strcmp(C{1,42},'secret')|strcmp(C{1,42},'perl')|strcmp(C{1,42},'yaga')|strcmp(C{1,42},'fdformat')|strcmp(C{1,42},'ffbconfig')|strcmp(C{1,42},'casesen')|strcmp(C{1,42},'ntfsdos')|strcmp(C{1,42},'ppmacro')|strcmp(C{1,42},'loadmodule')|strcmp(C{1,42},'sqlattack')|strcmp(C{1,42},'buffer_overflow')
        C{1,42}='2'; %this is a U2R type attack
    elseif strcmp(C{1,42},'normal')
        C{1,42}='1';   
    else 
         disp(sprintf('Could not detect attack type %s',C{1,42}));  
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
newtable = csvread('NSLKDDTestAltered');
for x=1:length(newtable(1,:))-1
    tempmax = max(newtable(:,x));
    tempmin = min(newtable(:,x));
    for y=1:length(newtable(:,1))-1 %we only go up to the 42nd column of the NSL KDD file
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
fprintf('Statistics for testing using the previously trained model (unbiased) on the NSL KDD 99 Test+ data: ');
[predicted_label, accuracy,prob_estimates] = predict(labels, features_sparse, model);
fprintf('Statistics for testing using the previously trained model (biased) on the NSL KDD 99 Test+ data: ');
[predicted_label1, accuracy1,prob_estimates1] = predict(labels, features_sparse, model1);

%we next process the training data for Test-21
fileID = fopen('NSLKDDTest-21.txt');
writeID = fopen('NSLKDDTest21Altered','wt');
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
    if strcmp(C{1,42},'portsweep') | strcmp(C{1,42},'saint') |strcmp(C{1,42},'ipsweep') | strcmp(C{1,42},'queso') | strcmp(C{1,42},'satan') | strcmp(C{1,42},'mscan') | strcmp(C{1,42},'ntinfoscan') | strcmp(C{1,42},'lsdomain') | strcmp(C{1,42},'illegal-sniffer')|strcmp(C{1,42},'nmap')
        C{1,42} = '5'; %this is a probe type attack
    elseif strcmp(C{1,42},'apache2')|strcmp(C{1,42},'smurf')|strcmp(C{1,42},'neptune')|strcmp(C{1,42},'dosnuke')|strcmp(C{1,42},'land')|strcmp(C{1,42},'pod')|strcmp(C{1,42},'back')|strcmp(C{1,42},'teardrop')|strcmp(C{1,42},'tcpreset')|strcmp(C{1,42},'syslogd')|strcmp(C{1,42},'crashiis')|strcmp(C{1,42},'arppoison')|strcmp(C{1,42},'mailbomb')|strcmp(C{1,42},'selfping')|strcmp(C{1,42},'processtable')|strcmp(C{1,42},'udpstorm')
        C{1,42} = '4'; %this is a denial of service type attack
    elseif strcmp(C{1,42},'diet')|strcmp(C{1,42},'worm')|strcmp(C{1,42},'snmpguess')|strcmp(C{1,42},'multihop')|strcmp(C{1,42},'netcat')|strcmp(C{1,42},'sendmail')|strcmp(C{1,42},'imap')|strcmp(C{1,42},'ncftp')|strcmp(C{1,42},'xlock')|strcmp(C{1,42},'xsnoop')|strcmp(C{1,42},'sshtrojan')|strcmp(C{1,42},'framespoof')|strcmp(C{1,42},'ppmacro')|strcmp(C{1,42},'guest')|strcmp(C{1,42},'netbus')|strcmp(C{1,42},'snmpgetattack')|strcmp(C{1,42},'ftp_write')|strcmp(C{1,42},'httptunnel')|strcmp(C{1,42},'phf')|strcmp(C{1,42},'named')|strcmp(C{1,42},'guess_passwd')|strcmp(C{1,42},'warezclient')|strcmp(C{1,42},'warezmaster')|strcmp(C{1,42},'spy')
        C{1,42}= '3'; %this is a R2L type attack
    elseif strcmp(C{1,42},'sechole')|strcmp(C{1,42},'rootkit')|strcmp(C{1,42},'xterm')|strcmp(C{1,42},'eject')|strcmp(C{1,42},'ps')|strcmp(C{1,42},'nukepw')|strcmp(C{1,42},'secret')|strcmp(C{1,42},'perl')|strcmp(C{1,42},'yaga')|strcmp(C{1,42},'fdformat')|strcmp(C{1,42},'ffbconfig')|strcmp(C{1,42},'casesen')|strcmp(C{1,42},'ntfsdos')|strcmp(C{1,42},'ppmacro')|strcmp(C{1,42},'loadmodule')|strcmp(C{1,42},'sqlattack')|strcmp(C{1,42},'buffer_overflow')
        C{1,42}='2'; %this is a U2R type attack
    elseif strcmp(C{1,42},'normal')
        C{1,42}='1';   
    else 
         disp(sprintf('Could not detect attack type %s',C{1,42}));  
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
newtable = csvread('NSLKDDTest21Altered');
for x=1:length(newtable(1,:))-1
    tempmax = max(newtable(:,x));
    tempmin = min(newtable(:,x));
    for y=1:length(newtable(:,1))-1 %we only go up to the 42nd column of the NSL KDD file
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
fprintf('Statistics for testing using the previously trained model (unbiased) on the NSL KDD 99 Test-21 data: ');
[predicted_label, accuracy,prob_estimates] = predict(labels, features_sparse, model);
fprintf('Statistics for testing using the previously trained model (biased) on the NSL KDD 99 Test-21 data: ');
[predicted_label1, accuracy1,prob_estimates1] = predict(labels, features_sparse, model1);
%total = length(A);
%datastored = textscan(fileID, '%s','Delimiter',',');
%fclose(fileID);
%newstr=datastored{1,1};
%labels=zeros(1,(length(newstr)/42));
%features =zeros(41, (length(newstr)/42));
%numobs=length(newstr)/42;
%for x=1:numobs
%    labels(1,x)=newstr{((x-1)*42+1),1};
%    for z=1:41
%        features(z,x)=newstr{((x-1)*42+1+z),1};
%    end    
%end
%{

%create neural networks with one, four, and eight hidden units, with the
%MLP function feedforwardnet, with the parameter specifying the number of
%hidden element units in the hidden layer
net=feedforwardnet(1);
net1=feedforwardnet(4);
net2=feedforwardnet(8);
[net,tr]=train(net,regrxtrain,regrttrain);
[net1,tr1]=train(net1,regrxtrain,regrttrain);
[net2,tr2]=train(net2,regrxtrain,regrttrain);
%we get the training output by applying our trained neural network to the
%input data
troutput=net(regrxtrain);
troutput1=net1(regrxtrain);
troutput2=net2(regrxtrain);
%we then calculate the training error
errorcounter=0;
errorcounter1=0;
errorcounter2=0;
for obcount=1:numobs
    for opcount=1:7
        errorcounter=(regrttrain(opcount,obcount)-troutput(opcount,obcount))^2;
        errorcounter1=(regrttrain(opcount,obcount)-troutput1(opcount,obcount))^2;
        errorcounter2=(regrttrain(opcount,obcount)-troutput2(opcount,obcount))^2;    
    end
end
%we normalize by dividing by the number of observations
errorcounter = errorcounter/numobs;
errorcounter1 = errorcounter1/numobs;
errorcounter2 = errorcounter2/numobs;
 disp(sprintf('Least-Squares Training Error for regression.tra over all observations with 1 hidden unit is %d for %d observations',errorcounter,numobs));
 disp(sprintf('Least-Squares Training Error for regression.tra over all observations with 4 hidden units is %d for %d observations',errorcounter1,numobs));
 disp(sprintf('Least-Squares Training Error for regression.tra over all observations with 8 hidden units is %d for %d observations',errorcounter2,numobs));
%we then get import the regression testing data and apply it to our trained
%neural networks
fileID = fopen('regression.tst');
datastored = textscan(fileID, '%s');
fclose(fileID);
newstr=datastored{1,1};
regrxtest=zeros(8,(length(newstr)/15));
regrttest=zeros(7, (length(newstr)/15));
numobs=length(newstr)/15;
for x=1:(length(newstr)/15)
    for y=1:8
        regrxtest(y,x)=strread(newstr{((x-1)*15+y),1});
    end
    for z=1:7
        regrttest(z,x)=strread(newstr{((x-1)*15+8+z),1});
    end    
end
%we get the training output by applying our trained neural network to the
%input data
tsoutput=net(regrxtest);
tsoutput1=net1(regrxtest);
tsoutput2=net2(regrxtest);
%we then calculate the training error
errorcounter=0;
errorcounter1=0;
errorcounter2=0;
for obcount=1:numobs
    for opcount=1:7
        errorcounter=(regrttest(opcount,obcount)-tsoutput(opcount,obcount))^2;
        errorcounter1=(regrttest(opcount,obcount)-tsoutput1(opcount,obcount))^2;
        errorcounter2=(regrttest(opcount,obcount)-tsoutput2(opcount,obcount))^2;    
    end
end
%we normalize by dividing by the number of observations
errorcounter = errorcounter/numobs;
errorcounter1 = errorcounter1/numobs;
errorcounter2 = errorcounter2/numobs;
disp(sprintf('Least-Squares Training Error for regression.tst over all observations with 1 hidden unit is %d for %d observations',errorcounter,numobs));
disp(sprintf('Least-Squares Training Error for regression.tst over all observations with 4 hidden units is %d for %d observations',errorcounter1,numobs));
disp(sprintf('Least-Squares Training Error for regression.tst over all observations with 8 hidden units is %d for %d observations',errorcounter2,numobs));

%we then move to task 2, to design a three layer neural network for
%classification, with 2 inputs and 2 classes, with 1, 2, and 4 hidden units
%in the hidden layer of our neural network.

%for task 2 we repeat essentially the same operation as task 1 for reading the data into the vector arrays,
%however we have to perform an extra step for classes to translate them from discrete to vector outputs, where '1'
%becomes [1 0] and '2' becomes [0 1] respectively.

fileID = fopen('classification.tra');
datastored = textscan(fileID, '%s');
fclose(fileID);
newstr=datastored{1,1};
xvec=zeros(2,(length(newstr)/3));
tvec=zeros(2,(length(newstr)/3));
classnum=zeros(1,(length(newstr)/3));
classnumcheck=zeros(1,(length(newstr)/3));
numobs=length(newstr)/3;
for x=1:(length(newstr)/3)
    for y=1:2
        xvec(y,x)=strread(newstr{((x-1)*3+y),1});
    end
    classnum(x)=strread(newstr{((x-1)*3+3),1});
    %based on the classnum value we do binary coding for the t vector
    if classnum(x)==1
        tvec(1,x)=1;
        tvec(2,x)=0;
    elseif classnum(x)==2
        tvec(1,x)=0;
        tvec(2,x)=1;
    else
    end
end
%create neural networks for pattern recognition (classification) with one, two, and four hidden units, with the
%MLP function patternnet, with the parameter specifying the number of
%hidden element units in the hidden layer
net=patternnet(1);
net1=patternnet(2);
net2=patternnet(4);
[net,tr]=train(net,xvec,tvec);
[net1,tr1]=train(net1,xvec,tvec);
[net2,tr2]=train(net2,xvec,tvec);
%we get the training output by applying our trained neural network to the
%input data
troutput=net(xvec);
troutput1=net1(xvec);
troutput2=net2(xvec);
%we translate the results into class number by assigning the index with the
%greater result as the class
tclasses=vec2ind(tvec);
classes=vec2ind(troutput);
classes1=vec2ind(troutput1);
classes2=vec2ind(troutput2);
%we then calculate the training accuracy
errorcounter=0;
errorcounter1=0;
errorcounter2=0;
for obcount=1:numobs
        if (tclasses(obcount)~=classes(obcount))
            errorcounter=errorcounter+1;
        end
        if (tclasses(obcount)~=classes1(obcount))
            errorcounter1=errorcounter1+1;
        end
        if (tclasses(obcount)~=classes2(obcount))
            errorcounter2=errorcounter2+1;
        end
end
 disp(sprintf('Training Accuracy for classification.tra over all observations with 1 hidden unit is %d percent for %d observations',(numobs-errorcounter)/numobs*100,numobs));
 disp(sprintf('Training Accuracy for classification.tra over all observations with 2 hidden units is %d percent for %d observations',(numobs-errorcounter1)/numobs*100,numobs));
 disp(sprintf('Training Accuracy for classification.tra over all observations with 4 hidden units is %d percent for %d observations',(numobs-errorcounter2)/numobs*100,numobs));
%having trained the neural networks we then import the testing data from
%classification.tst

fileID = fopen('classification.tst');
datastored = textscan(fileID, '%s');
fclose(fileID);
newstr=datastored{1,1};
xvec=zeros(2,(length(newstr)/3));
tvec=zeros(2,(length(newstr)/3));
classnum=zeros(1,(length(newstr)/3));
classnumcheck=zeros(1,(length(newstr)/3));
numobs=length(newstr)/3;
for x=1:(length(newstr)/3)
    for y=1:2
        xvec(y,x)=strread(newstr{((x-1)*3+y),1});
    end
    classnum(x)=strread(newstr{((x-1)*3+3),1});
    %based on the classnum value we do binary coding for the t vector
    if classnum(x)==1
        tvec(1,x)=1;
        tvec(2,x)=0;
    elseif classnum(x)==2
        tvec(1,x)=0;
        tvec(2,x)=1;
    else
    end
end

%we get the testing output by applying our trained neural network to the
%input data
troutput=net(xvec);
troutput1=net1(xvec);
troutput2=net2(xvec);
%we translate the results into class number by assigning the index with the
%greater result as the class
tclasses=vec2ind(tvec);
classes=vec2ind(troutput);
classes1=vec2ind(troutput1);
classes2=vec2ind(troutput2);
%we then calculate the training accuracy
errorcounter=0;
errorcounter1=0;
errorcounter2=0;
for obcount=1:numobs
        if (tclasses(obcount)~=classes(obcount))
            errorcounter=errorcounter+1;
        end
        if (tclasses(obcount)~=classes1(obcount))
            errorcounter1=errorcounter1+1;
        end
        if (tclasses(obcount)~=classes2(obcount))
            errorcounter2=errorcounter2+1;
        end
end
 disp(sprintf('Testing Accuracy for classification.tst over all observations with 1 hidden unit is %d percent for %d observations',(numobs-errorcounter)/numobs*100,numobs));
 disp(sprintf('Testing Accuracy for classification.tst over all observations with 2 hidden units is %d percent for %d observations',(numobs-errorcounter1)/numobs*100,numobs));
 disp(sprintf('Testing Accuracy for classification.tst over all observations with 4 hidden units is %d percent for %d observations',(numobs-errorcounter2)/numobs*100,numobs));

%{
for task 3 we repeat essentially the same operation as task 2, where we now
have 16 inputs and 10 classes, and we use 5, 10, and 13 hidden units in the
hidden layer of the MLP
%}
fileID = fopen('zipcode.tra');
datastored = textscan(fileID, '%s');
fclose(fileID);
newstr=datastored{1,1};
xvec=zeros(16,(length(newstr)/17));
tvec=zeros(10,(length(newstr)/17));
classnum=zeros(1,(length(newstr)/17));
classnumcheck=zeros(1,(length(newstr)/17));
numobs=length(newstr)/17;
for x=1:(length(newstr)/17)
    for y=1:17
        xvec(y,x)=strread(newstr{((x-1)*17+y),1});
    end
    classnum(x)=strread(newstr{((x-1)*17+17),1});
    %based on the classnum value we do binary coding for the t vector
    tvec(classnum(x),x)=1;
end

%create neural networks for pattern recognition (classification) with one, two, and four hidden units, with the
%MLP function patternnet, with the parameter specifying the number of
%hidden element units in the hidden layer
net=patternnet(5);
net1=patternnet(10);
net2=patternnet(13);
[net,tr]=train(net,xvec,tvec);
[net1,tr1]=train(net1,xvec,tvec);
[net2,tr2]=train(net2,xvec,tvec);
%we get the training output by applying our trained neural network to the
%input data
troutput=net(xvec);
troutput1=net1(xvec);
troutput2=net2(xvec);
%we translate the results into class number by assigning the index with the
%greater result as the class
tclasses=vec2ind(tvec);
classes=vec2ind(troutput);
classes1=vec2ind(troutput1);
classes2=vec2ind(troutput2);
%we then calculate the training accuracy
errorcounter=0;
errorcounter1=0;
errorcounter2=0;
for obcount=1:numobs
        if (tclasses(obcount)~=classes(obcount))
            errorcounter=errorcounter+1;
        end
        if (tclasses(obcount)~=classes1(obcount))
            errorcounter1=errorcounter1+1;
        end
        if (tclasses(obcount)~=classes2(obcount))
            errorcounter2=errorcounter2+1;
        end
end
 disp(sprintf('Training Accuracy for zipcode.tra over all observations with 5 hidden unit is %d percent for %d observations',(numobs-errorcounter)/numobs*100,numobs));
 disp(sprintf('Training Accuracy for zipcode.tra over all observations with 10 hidden units is %d percent for %d observations',(numobs-errorcounter1)/numobs*100,numobs));
 disp(sprintf('Training Accuracy for zipcode.tra over all observations with 13 hidden units is %d percent for %d observations',(numobs-errorcounter2)/numobs*100,numobs));
%having trained the neural networks we then import the testing data from
%zipcode.tst
fileID = fopen('zipcode.tst');
datastored = textscan(fileID, '%s');
fclose(fileID);
newstr=datastored{1,1};
xvec=zeros(16,(length(newstr)/17));
tvec=zeros(10,(length(newstr)/17));
classnum=zeros(1,(length(newstr)/17));
classnumcheck=zeros(1,(length(newstr)/17));
numobs=length(newstr)/17;
for x=1:(length(newstr)/17)
    for y=1:17
        xvec(y,x)=strread(newstr{((x-1)*17+y),1});
    end
    classnum(x)=strread(newstr{((x-1)*17+17),1});
    %based on the classnum value we do binary coding for the t vector
    tvec(classnum(x),x)=1;
end

%we get the testing output by applying our trained neural network to the
%input data
troutput=net(xvec);
troutput1=net1(xvec);
troutput2=net2(xvec);
%we translate the results into class number by assigning the index with the
%greater result as the class
tclasses=vec2ind(tvec);
classes=vec2ind(troutput);
classes1=vec2ind(troutput1);
classes2=vec2ind(troutput2);
%we then calculate the training accuracy
errorcounter=0;
errorcounter1=0;
errorcounter2=0;
for obcount=1:numobs
        if (tclasses(obcount)~=classes(obcount))
            errorcounter=errorcounter+1;
        end
        if (tclasses(obcount)~=classes1(obcount))
            errorcounter1=errorcounter1+1;
        end
        if (tclasses(obcount)~=classes2(obcount))
            errorcounter2=errorcounter2+1;
        end
end
 disp(sprintf('Testing Accuracy for zipcode.tst over all observations with 5 hidden unit is %d percent for %d observations',(numobs-errorcounter)/numobs*100,numobs));
 disp(sprintf('Testing Accuracy for zipcode.tst over all observations with 10 hidden units is %d percent for %d observations',(numobs-errorcounter1)/numobs*100,numobs));
 disp(sprintf('Testing Accuracy for zipcode.tst over all observations with 13 hidden units is %d percent for %d observations',(numobs-errorcounter2)/numobs*100,numobs));

 
 
 %{
for task 4 we repeat essentially the same operation as tasks 2 and 3, where we now
use the SVM classifier instead.  For task 2 we use the fitcsvm function
for binary classification utilizing kernel functions, and then for task 3
we use the fitcecoc function which is a combination of binary SVM
classifiers, where the default kernel function used is linear
%}

fileID = fopen('classification.tra');
datastored = textscan(fileID, '%s');
fclose(fileID);
newstr=datastored{1,1};
xvec=zeros(2,(length(newstr)/3));
tvec=zeros(2,(length(newstr)/3));
classnum=zeros(1,(length(newstr)/3));
classnumcheck=zeros(1,(length(newstr)/3));
numobs=length(newstr)/3;
for x=1:(length(newstr)/3)
    for y=1:2
        xvec(y,x)=strread(newstr{((x-1)*3+y),1});
    end
    classnum(x)=strread(newstr{((x-1)*3+3),1});
    %based on the classnum value we do binary coding for the t vector
    if classnum(x)==1
        tvec(1,x)=1;
        tvec(2,x)=0;
    elseif classnum(x)==2
        tvec(1,x)=0;
        tvec(2,x)=1;
    else
    end
end
%create neural networks for pattern recognition (classification) with one, two, and four hidden units, with the
%MLP function patternnet, with the parameter specifying the number of
%hidden element units in the hidden layer
tclasses=vec2ind(tvec);
gvec=transpose(xvec);
%the fitcsvm function uses where each ROW is an observation and in order to
%perform this we must transpose the xvec matrix, and where the class labels
%are not vectors but single indices, which we accomplish through the
%vec2ind function above
svmmodel=fitcsvm(gvec,tclasses);
%we get the training output in terms of class number by applying our trained neural network to the
%input data
troutput=predict(svmmodel,gvec);
%we then calculate the training accuracy
errorcounter=0;
for obcount=1:numobs
        if (tclasses(obcount)~=troutput(obcount))
            errorcounter=errorcounter+1;
        end
end
 disp(sprintf('Training Accuracy for classification.tra over all observations with the binary SVM classifier is %d percent for %d observations',(numobs-errorcounter)/numobs*100,numobs));

 
 %having trained the neural networks we then import the testing data from
%classification.tst

fileID = fopen('classification.tst');
datastored = textscan(fileID, '%s');
fclose(fileID);
newstr=datastored{1,1};
xvec=zeros(2,(length(newstr)/3));
tvec=zeros(2,(length(newstr)/3));
classnum=zeros(1,(length(newstr)/3));
classnumcheck=zeros(1,(length(newstr)/3));
numobs=length(newstr)/3;
for x=1:(length(newstr)/3)
    for y=1:2
        xvec(y,x)=strread(newstr{((x-1)*3+y),1});
    end
    classnum(x)=strread(newstr{((x-1)*3+3),1});
    %based on the classnum value we do binary coding for the t vector
    if classnum(x)==1
        tvec(1,x)=1;
        tvec(2,x)=0;
    elseif classnum(x)==2
        tvec(1,x)=0;
        tvec(2,x)=1;
    else
    end
end
gvec=transpose(xvec);
%we get the testing output by applying our trained neural network to the
%input data
troutput=predict(svmmodel,gvec);
%we translate the results into class number by assigning the index with the
%greater result as the class
tclasses=vec2ind(tvec);
%we then calculate the training accuracy
errorcounter=0;
for obcount=1:numobs
        if (tclasses(obcount)~=troutput(obcount))
            errorcounter=errorcounter+1;
        end
end
 disp(sprintf('Testing Accuracy for classification.tst over all observations with the binary SVM classifier is %d percent for %d observations',(numobs-errorcounter)/numobs*100,numobs));

 %we now perform task 3 using a multiclass SVM classifier, fitcecoc(X,Y),
 %which uses a combination of binary SVM classifiers, using a linear kernel
 %function by default
 
fileID = fopen('zipcode.tra');
datastored = textscan(fileID, '%s');
fclose(fileID);
newstr=datastored{1,1};
xvec=zeros(16,(length(newstr)/17));
tvec=zeros(10,(length(newstr)/17));
classnum=zeros(1,(length(newstr)/17));
classnumcheck=zeros(1,(length(newstr)/17));
numobs=length(newstr)/17;
for x=1:(length(newstr)/17)
    for y=1:17
        xvec(y,x)=strread(newstr{((x-1)*17+y),1});
    end
    classnum(x)=strread(newstr{((x-1)*17+17),1});
    %based on the classnum value we do binary coding for the t vector
    tvec(classnum(x),x)=1;
end
gvec=transpose(xvec);
tclasses=vec2ind(tvec);
svmmodel=fitcecoc(gvec,tclasses);
%we get the training output in terms of class number by applying our
%trained SVM classifier
%input data
troutput=predict(svmmodel,gvec);
%we then calculate the training accuracy
errorcounter=0;
for obcount=1:numobs
        if (tclasses(obcount)~=troutput(obcount))
            errorcounter=errorcounter+1;
        end
end
 disp(sprintf('Training Accuracy for zipcode.tra over all observations with the multiclass SVM classifier is %d percent for %d observations',(numobs-errorcounter)/numobs*100,numobs));
%having trained the SVM classifier we then import the testing data from
%zipcode.tst
fileID = fopen('zipcode.tst');
datastored = textscan(fileID, '%s');
fclose(fileID);
newstr=datastored{1,1};
xvec=zeros(16,(length(newstr)/17));
tvec=zeros(10,(length(newstr)/17));
classnum=zeros(1,(length(newstr)/17));
classnumcheck=zeros(1,(length(newstr)/17));
numobs=length(newstr)/17;
for x=1:(length(newstr)/17)
    for y=1:17
        xvec(y,x)=strread(newstr{((x-1)*17+y),1});
    end
    classnum(x)=strread(newstr{((x-1)*17+17),1});
    %based on the classnum value we do binary coding for the t vector
    tvec(classnum(x),x)=1;
end
gvec=transpose(xvec);
tclasses=vec2ind(tvec);
%we get the testing output in terms of class number by applying our trained neural network to the
%input data
troutput=predict(svmmodel,gvec);
%we then calculate the training accuracy
errorcounter=0;
for obcount=1:numobs
        if (tclasses(obcount)~=troutput(obcount))
            errorcounter=errorcounter+1;
        end
end
 disp(sprintf('Testing Accuracy for zipcode.tst over all observations with the multiclass SVM classifier is %d percent for %d observations',(numobs-errorcounter)/numobs*100,numobs));

%}