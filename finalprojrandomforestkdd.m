%{
Rohit Dewan
%}

%{
for the random forest task with training a random forest classifier using the original 10% KDD data,
 we use the same preprocessing steps as with the KDD and NSL KDD data sets.
 That is, we use the preprocessed file from the SVM classifier trained with
 the original 10% KDD data, where we preprocessed the categorical variables
 and had scaled all integer values, without affecting binary values (they
 stayed the same).  THus we can use the already preprocessed KDD 10%
 training data, and preprocessed test data for the originial KDD
 'corrected' values, the NSL Test+ data set, and the Test-21 data set
Reading in the preprocessed tables, we then train 4 different random forest models with parameters
of 10/1, 25/2, 50/4, 500/8 trees/features sampled. 

%}
%read previously preprocessed original KDD 10% training data
newtable = csvread('kddcupaltered');
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
%then this can be used by the classRF_train wrapper class to develop 4
%Random forest models with trees/features sampled as described above
%training model
labels = newtable(:,length(newtable(1,:)));
features = newtable(:,1:(length(newtable(1,:))-1));
model = classRF_train(features,labels,10,1);
Y_hat = classRF_predict(features,model);
fprintf('\nThe training error for training using random forest on the original KDD data training set using 10 trees and 1 feature sampled randomly is %f\n',   length(find(Y_hat~=labels))/length(labels));
model1 = classRF_train(features,labels, 25,2);
Y_hat = classRF_predict(features,model1);
fprintf('\nThe training error for training using random forest on the original KDD data training set using 25 trees and 2 features sampled randomly is %f\n',   length(find(Y_hat~=labels))/length(labels));
model2 = classRF_train(features,labels, 50,4);
Y_hat = classRF_predict(features,model2);
fprintf('\nThe training error for training using random forest on the original NSL KDD data training set using 50 trees and 4 features sampled randomly is %f\n',   length(find(Y_hat~=labels))/length(labels));
model3 = classRF_train(features,labels, 500,8);
Y_hat = classRF_predict(features,model3);
fprintf('\nThe training error for training using random forest on the original NSL KDD data training set using 500 trees and 8 features sampled randomly is %f\n',   length(find(Y_hat~=labels))/length(labels));
%we next use the preprocessed data for the 'corrected' testing data from
%the original KDD dataset
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
%then this can be used by the class RF_predict wrpaper to develop a L2 regularized
%training model
labels = newtable(:,length(newtable(1,:)));
features = newtable(:,1:(length(newtable(1,:))-1));
Y_hat = classRF_predict(features,model);
fprintf('\nThe testing error of 10 trees and 1 feature on the original KDD dataset is  %f\n',   length(find(Y_hat~=labels))/length(labels));
Y_hat = classRF_predict(features,model1);
fprintf('\nThe testing error of 25 trees and 2 features on the original KDD dataset is  %f\n',   length(find(Y_hat~=labels))/length(labels));
Y_hat = classRF_predict(features,model2);
fprintf('\nThe testing error of 50 trees and 4 features on the original KDD dataset is  %f\n',   length(find(Y_hat~=labels))/length(labels));
Y_hat = classRF_predict(features,model3);
fprintf('\nThe testing error of 500 trees and 8 features on the original KDD dataset is  %f\n',   length(find(Y_hat~=labels))/length(labels));


%we next process the testing data for the preprocessed Test+ set
newtable = csvread('NSLKDDTestAlteredkdd');
for x=1:length(newtable(1,:))-2 %here because there is an extra feature column 41 corresponding to the 41st feature of the KDD set is now the length-2
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
%then this can be used by the classRF_predict wrapper class to predict
%based on the earlier developed models
labels = newtable(:,length(newtable(1,:))-1);
features = newtable(:,1:(length(newtable(1,:))-2));
Y_hat = classRF_predict(features,model);
fprintf('\nThe testing error of 10 trees and 1 feature on the NSL Test+ dataset is  %f\n',   length(find(Y_hat~=labels))/length(labels));
Y_hat = classRF_predict(features,model1);
fprintf('\nThe testing error of 25 trees and 2 features on the NSL Test+ dataset is  %f\n',   length(find(Y_hat~=labels))/length(labels));
Y_hat = classRF_predict(features,model2);
fprintf('\nThe testing error of 50 trees and 4 features on the NSL Test+ dataset is  %f\n',   length(find(Y_hat~=labels))/length(labels));
Y_hat = classRF_predict(features,model3);
fprintf('\nThe testing error of 500 trees and 8 features on the NSL Test+ dataset is  %f\n',   length(find(Y_hat~=labels))/length(labels));


%we next process the test data for Test-21
newtable = csvread('NSLKDDTest21Alteredkdd');
for x=1:length(newtable(1,:))-2 %here because there is an extra feature column 41 corresponding to the 41st feature of the KDD set is now the length-2
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
%and the first through (last-1) columns to features, 
%then this can be used by the classRF_predict wrapper class to predict
%based on the earlier developed models
labels = newtable(:,length(newtable(1,:))-1);
features = newtable(:,1:(length(newtable(1,:))-2));
Y_hat = classRF_predict(features,model);
fprintf('\nThe testing error of 10 trees and 1 feature on the NSL Test-21 dataset is  %f\n',   length(find(Y_hat~=labels))/length(labels));
Y_hat = classRF_predict(features,model1);
fprintf('\nThe testing error of 25 trees and 2 features on the NSL Test-21 dataset is  %f\n',   length(find(Y_hat~=labels))/length(labels));
Y_hat = classRF_predict(features,model2);
fprintf('\nThe testing error of 50 trees and 4 features on the NSL Test-21 dataset is  %f\n',   length(find(Y_hat~=labels))/length(labels));
Y_hat = classRF_predict(features,model3);
fprintf('\nThe testing error of 500 trees and 8 features on the NSL Test-21 dataset is  %f\n',   length(find(Y_hat~=labels))/length(labels));

