%{
Rohit Dewan
%}

%{
for the random forest tast, we use the same preprocessing steps as with the KDD and NSL KDD data sets,
 and train different numbers of trees sampling a number of features for each tree randomly, and we vary
 both the 1. numbers of trees and 2. number of features randomly sampled to find optimal
performance characteristics.  

In particular, we use the Proj. 2 parameters of 10/1, 25/2, 50/4, 500/8 trees/features sampled. 
%}

newtable = csvread('NSLKDDTrain20Altered');
for x=1:length(newtable(1,:))-2 %here because there is an extra feature column 41 corresponding to the 41st feature of the KDD set is now the length-2
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
%and the first through (last-1) columns to features
%then this can be used by the random forest model

labels = newtable(:,length(newtable(1,:))-1);
features = newtable(:,1:(length(newtable(1,:))-2));
model = classRF_train(features,labels,10,1);
Y_hat = classRF_predict(features,model);
fprintf('\nThe training error for training using random forest on the 20 percent NSL KDD data training set using 10 trees and 1 feature sampled randomly is %f\n',   length(find(Y_hat~=labels))/length(labels));
model1 = classRF_train(features,labels, 25,2);
Y_hat = classRF_predict(features,model1);
fprintf('\nThe training error for training using random forest on the 20 percent NSL KDD data training set using 25 trees and 2 features sampled randomly is %f\n',   length(find(Y_hat~=labels))/length(labels));
model2 = classRF_train(features,labels, 50,4);
Y_hat = classRF_predict(features,model2);
fprintf('\nThe training error for training using random forest on the 20 percent NSL KDD data training set using 50 trees and 4 features sampled randomly is %f\n',   length(find(Y_hat~=labels))/length(labels));
%for feature importance
clear extra_options
extra_options.importance=1;
model3 = classRF_train(features,labels, 500,8, extra_options);
figure('Name','Importance Plots')
subplot(2,1,1);
bar(model3.importance(:,end-1));xlabel('feature');ylabel('magnitude');
title('Mean decrease in Accuracy of OOB Rate with permutation');
Y_hat = classRF_predict(features,model3);
fprintf('\nThe training error for training using random forest on the 20 percent NSL KDD data training set using 500 trees and 8 features sampled randomly is %f\n',   length(find(Y_hat~=labels))/length(labels));

newtable = csvread('NSLKDDTestAltered20');
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
%and the first through (last-1) columns to features
%then this can be used by the random forest model

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




%we next process the training data for Test-21

newtable = csvread('NSLKDDTest21Altered20');
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
%and the first through (last-1) columns to features
%then this can be used by the random forest model

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

newtable = csvread('newcorrected20');
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
%and the first through (last-1) columns to features
%then this can be used by the random forest model

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