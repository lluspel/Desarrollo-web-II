print ("IMPORTING LIBRARIES...")
import pandas as pd


print ("LOADING DATASETS...")
df_train = pd.read_csv("http://lluspel.pythonanywhere.com/static/uploads/{{competion.username}}__{{competion.competioncode}}__train.csv")
df_train.head()

df_test = pd.read_csv("http://lluspel.pythonanywhere.com/static/uploads/{{competion.username}}__{{competion.competioncode}}__test.csv")
df_test.head()

print ("STEP 1: DOING MY TRANSFORMATIONS...")
df_train = df_train.fillna(0)
df_test = df_test.fillna(0)

print ("STEP 2: SELECTING CHARACTERISTICS TO ENTER INTO THE MODEL...")
def get_specific_columns(df, data_types, to_ignore = list(), ignore_target = False):
    columns = df.select_dtypes(include=data_types).columns
    if ignore_target:
        columns = filter(lambda x: x not in to_ignore, list(columns))
    return list(columns)

output_var = df_train.columns[-1]
in_model = get_specific_columns(df_train, ["float64", "int64"], [output_var], ignore_target = True)

print ("STEP 3: DEVELOPING THE MODEL...")
X_train = df_train[in_model]
y_train = df_train[output_var]
X_test = df_test[in_model]

from sklearn.linear_model import LogisticRegression
clf = LogisticRegression(random_state=0, solver='lbfgs')
fitted_model = clf.fit(X_train, y_train)
pred_train = fitted_model.predict_proba(X_train)[:,1]
pred_test  = fitted_model.predict_proba(X_test)[:,1]

print ("STEP 4: ASSESSING THE MODEL...")
# CALCULATING GINI PERFORMANCE ON DEVELOPMENT SAMPLE
from sklearn.metrics import roc_auc_score
gini_score = 2*roc_auc_score(y_train, pred_train)-1
print ("GINI DEVELOPMENT=", gini_score)

def KS(b,a):
    """Function that received two parameters; first: a binary variable representing 0=good and 1=bad,
    and then a second variable with the prediction of the first variable, the second variable can be continuous,
    integer or binary - continuous is better. Finally, the function returns the KS Statistics of the two lists."""
    try:
        tot_bads=1.0*sum(b)
        tot_goods=1.0*(len(b)-tot_bads)
        elements = zip(*[a,b])
        elements = sorted(elements,key= lambda x: x[0])
        elements_df = pd.DataFrame({'probability': b,'gbi': a})
        pivot_elements_df = pd.pivot_table(elements_df, values='probability', index=['gbi'], aggfunc=[sum,len]).fillna(0)
        max_ks = perc_goods = perc_bads = cum_perc_bads = cum_perc_goods = 0
        for i in range(len(pivot_elements_df)):
            perc_goods =  (pivot_elements_df.iloc[i]['len'] - pivot_elements_df.iloc[i]['sum']) / tot_goods
            perc_bads = pivot_elements_df.iloc[i]['sum']/ tot_bads
            cum_perc_goods += perc_goods
            cum_perc_bads += perc_bads
            A = cum_perc_bads-cum_perc_goods
            if abs(A['probability']) > max_ks:
                max_ks = abs(A['probability'])
    except:
        max_ks = 0
    return max_ks


"""
WHAT IS GINI AND KS?
* watch this video for reference: https://youtu.be/MiBUBVUC8kE
"""

print ("STEP 5: SUBMITTING THE RESULTS...")
import requests
from requests.auth import HTTPBasicAuth
df_test['pred'] = pred_test
df_test['id'] = df_test.iloc[:,0]
df_test_tosend = df_test[['id','pred']]

filename = "df_test_tosend.csv"
df_test_tosend.to_csv(filename, sep=',')
url = 'http://lluspel.pythonanywhere.com//uploadpredictions/{{competion.competioncode}}'
files = {'file': (filename, open(filename, 'rb'))}

"""
To compete in this challenge, please create an user at my teaching website: http://lluspel.pythonanywhere.com
and replace below where it says:
* my_user_name_goes_here
* my_password_goes_here
"""


rsub = requests.post(url, files=files, auth=HTTPBasicAuth("{{current_user.username}}", "{{current_user.password}}"))
resp_str = str(rsub.text)
print ("RESULT SUBMISSION: ", resp_str)