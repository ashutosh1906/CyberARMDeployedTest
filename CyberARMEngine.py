import ProjectConfigFile,Utitilities,TestCases
from z3 import *
import time
################################################################################## Global Variables ################################################################
threat_action_name_list = []
selected_security_controls = []
threat_id_for_all_assets = []
threat_action_id_list_for_all_assets = []
affordable_budget = [100000, 100000]
################################################################################## End Global Variables ################################################################

def SMT_Solver(asset_index,security_control_list,threat_action_list,threat_list,asset_enterprise_list):
    # USER_DEFINED_SMT_TRUE = 1
    # USER_DEFINED_SMT_FALSE = 0
    print "Check the imposed risk by all threats"
    gloabl_imposed_risk = 0
    for threat in threat_id_for_all_assets[asset_index]:
        gloabl_imposed_risk += threat_list[threat].threat_impact_asset[asset_index]
        # print "Threat ID %s : %s Value %s" % (threat,threat_list[threat].primary_key,threat_list[threat].threat_impact_asset[asset_index])
    print "Maximum Risk %s" % (gloabl_imposed_risk)

    threat_action_id_to_position_roll = {}
    for threat_act_index in range(len(threat_action_id_list_for_all_assets[asset_index])):
        threat_action_id_to_position_roll[threat_action_id_list_for_all_assets[asset_index][threat_act_index]] = threat_act_index

    print "Threat Action Index for this asset : %s" % (threat_action_id_to_position_roll)
    start_time = time.time()
    print selected_security_controls[asset_index]
    print threat_action_id_list_for_all_assets[asset_index]
    ##################################################################### Declare Variables ############################################################################
    security_controls_bool_SMT = [Bool("sc_control_bool_%s"%(i)) for i in range(len(selected_security_controls[asset_index]))]
    print "z3 Boolean Security Controls %s" % (security_controls_bool_SMT)
    security_controls_flag_SMT = [Int("sc_control_flag_%s"%(i)) for i in range(len(selected_security_controls[asset_index]))]
    threat_action_security_control_prob_SMT = [
                                    [
                                        Real("ta_%s_%s"%(i,j)) for j in range(len(threat_action_list[i].asset_applicable_security_controls))
                                    ]
                                    for i in threat_action_id_list_for_all_assets[asset_index]
                                 ]
    threat_action_success_prob_SMT = [Real("TA_%s"%(i)) for i in threat_action_id_list_for_all_assets[asset_index]]
    print threat_action_security_control_prob_SMT[1][2]
    for i in range(len(threat_action_security_control_prob_SMT)):
        ta_id = threat_action_id_list_for_all_assets[asset_index][i]
        print "Threat Action : (%s,%s,%s)" % (threat_action_security_control_prob_SMT[i], threat_action_list[ta_id].asset_applicable_security_controls,
                                              threat_action_list[ta_id].prob_given_threat_asset[asset_enterprise_list[asset_index][0]])
        print "Threat Action Success Mul(:Sec_control) === (%s)" % (threat_action_success_prob_SMT[i])

    threat_defense_success_SMT = [
                                [
                                    Real("t_%s_%s"%(i,j))for j in threat_list[i].asset_threat_action
                                ]
                                for i in threat_id_for_all_assets[asset_index]
                             ]
    print threat_defense_success_SMT[1][1]
    for i in range(len(threat_defense_success_SMT)):
        print "Threat %s" % (threat_defense_success_SMT[i])

    security_control_cost_SMT = [Real("Sc_%s"%(i)) for i in selected_security_controls[asset_index]]
    print "Security Controls  %s" % (security_control_cost_SMT)
    total_security_control_cost_SMT = Real("total_investment_cost")
    threat_failure_probability_SMT = [Real("T_f_%s" % (i)) for i in threat_id_for_all_assets[asset_index]]
    residual_risk_SMT = Real("residual_risk_SMT")
    print "Threat Failure Probability %s" % (threat_failure_probability_SMT)

    ################################################################################### Create SMT Environment #######################################################################
    set_option(rational_to_decimal=True)
    set_option(precision=30)

    ################################################################################### Declare the Model Checker ###################################################################
    cyberARM = Solver()

    ############################################################################### ADD Constraints ####################################################################################
    #################################### 1.1 Security Control Cost Constraint ##########################################
    sec_control_list_smt = selected_security_controls[asset_index]
    size_sec_control_list_smt = len(sec_control_list_smt)
    security_control_cost_constraint = [security_control_cost_SMT[i]==If(security_controls_bool_SMT[i],security_control_list[sec_control_list_smt[i]].investment_cost,0) for i in range(size_sec_control_list_smt)]
    total_security_control_cost_constraint = (total_security_control_cost_SMT == sum(security_control_cost_SMT))
    cyberARM.add(security_control_cost_constraint)
    cyberARM.add(total_security_control_cost_constraint)
    cyberARM.add(total_security_control_cost_SMT > 40000)
    cyberARM.add(total_security_control_cost_SMT <= affordable_budget[asset_index])

    ########################################### 1.2 Security Control Selection Constraint ######################################
    security_controls_flag_SMT = [security_controls_flag_SMT[i]==If(security_controls_bool_SMT[i],1,0) for i in range(size_sec_control_list_smt)]
    cyberARM.add(security_controls_flag_SMT)

    ######################################## 1.3 Threat Action Constraint ######################################################
    # threat_action_security_control_constraibt = [
    #                                                 [threat_action_security_control_prob_SMT[threat_action_id_to_position_roll[threat_action]][threat_action_list[threat_action].asset_security_control_index[sec_control_list_smt[sec_control_index]]]
    #                                                     for threat_action in security_control_list[sec_control_list_smt[sec_control_index]].asset_threat_action_list
    #                                                 ] for sec_control_index in range(size_sec_control_list_smt)
    #                                             ]
    print "*************************************** Check ***************************************************"
    for sec_control_index in range(size_sec_control_list_smt):
        print "Security Control ID : (%s,%s)" % (sec_control_list_smt[sec_control_index],security_control_list[sec_control_list_smt[sec_control_index]].primary_key)
        for threat_action in security_control_list[sec_control_list_smt[sec_control_index]].asset_threat_action_list:
            print "Threat Action ID : %s" % (threat_action)
            threat_action_index = threat_action_id_to_position_roll[threat_action]
            print "Which Threat Action to Update : %s" % (threat_action_index)
            threat_action_security_control_index = threat_action_list[threat_action].asset_security_control_index[sec_control_list_smt[sec_control_index]]
            print "Where to update : %s" % (threat_action_security_control_index)
            effect_sec_ta = security_control_list[sec_control_list_smt[sec_control_index]].threat_action_effectiveness[threat_action]
            print "Security Control Effectiveness %s" % (effect_sec_ta)
            cyberARM.add(threat_action_security_control_prob_SMT[threat_action_index][threat_action_security_control_index]==If(security_controls_bool_SMT[sec_control_index],(1-effect_sec_ta),1))

    ############################################################### 1.3.2 Threat Action Success Constraint ####################################################################
    # aaTest = 10
    for threat_action_id in range(len(threat_action_id_list_for_all_assets[asset_index])):
        print "Threat Action ID : %s %s SMT %s" % (threat_action_id_list_for_all_assets[asset_index][threat_action_id],threat_action_id,threat_action_security_control_prob_SMT[threat_action_id])
        if len(threat_action_security_control_prob_SMT[threat_action_id]) > 0 :
            cyberARM.add(threat_action_success_prob_SMT[threat_action_id]==reduce(lambda x,y:x*y,threat_action_security_control_prob_SMT[threat_action_id]))
        else:
            cyberARM.add(threat_action_success_prob_SMT[threat_action_id]==1)

    ########################################################### 1.4 Threat Success Constraint ################################################################################
    for threat in threat_id_for_all_assets[asset_index]:
        print " Threat ID : %s" % (threat)
        threat_index = threat_id_for_all_assets[asset_index].index(threat)
        print " Threat SMT : %s" % (threat_defense_success_SMT[threat_index])
        print "Threat Action : %s" % (threat_list[threat].asset_threat_action)
        threat_action_index = 0
        for threat_action_id in threat_list[threat].asset_threat_action:
            print "Threat Action ID %s" % (threat_action_id)
            print "Threat SMT %s" % (threat_defense_success_SMT[threat_index][threat_action_index])
            system_threat_action_id = threat_action_id_to_position_roll[threat_action_id]
            print "ID for this asset %s" % (system_threat_action_id)
            print "Threat Action Success %s" % (threat_action_success_prob_SMT[system_threat_action_id])
            print "Threat Action Probability %s" % (threat_list[threat].asset_threat_action_prob[threat_action_index])
            cyberARM.add(threat_defense_success_SMT[threat_index][threat_action_index]==(1-threat_action_success_prob_SMT[system_threat_action_id]*threat_list[threat].asset_threat_action_prob[threat_action_index]))
            threat_action_index += 1


        print " Threat Action Probability : %s" % (threat_list[threat].asset_threat_action_prob)
        print "Threat Impact : %s" % (threat_list[threat].threat_impact_asset[asset_index])

        ######################################################## 1.5 Threat Failure Probability ####################################################
    print "************************************** Predict Threat Failure Probability ******************************************"
    for threat_index in range(len(threat_failure_probability_SMT)):
        threat_id = threat_id_for_all_assets[asset_index][threat_index]
        print "Threat ID %s" % (threat_id)
        print "Threat ID SMT %s" % (threat_failure_probability_SMT[threat_index])
        print "Threat Action of ID %s" % (threat_list[threat_id].asset_threat_action)
        print "Threat ACtion ID SMT %s" % (threat_defense_success_SMT[threat_index])
        print "Threat Impact %s" % (threat_list[threat_id].threat_impact_asset[asset_index])
        if len(threat_list[threat_id].asset_threat_action) > 0:
            cyberARM.add(threat_failure_probability_SMT[threat_index]==((1-reduce(lambda x,y:x*y,threat_defense_success_SMT[threat_index]))*threat_list[threat_id].threat_impact_asset[asset_index]))
        else:
            cyberARM.add(threat_failure_probability_SMT[threat_index] == threat_list[threat_id].threat_impact_asset[asset_index])

        ################################################## 1.6 Affordable Risk ########################################################
        cyberARM.add(residual_risk_SMT==sum(threat_failure_probability_SMT))

    satisfiability = cyberARM.check()
    if satisfiability == z3.sat:
        print "Model is ---> "
        recommended_CDM = cyberARM.model()
        print recommended_CDM

        ##################################################### Threat Failure Probability #################################
        for i in range(len(threat_failure_probability_SMT)):
            print "ID %s Impact %s Success Prob %s Value %s" % (threat_id_for_all_assets[asset_index][i],threat_list[threat_id_for_all_assets[asset_index][i]].threat_impact_asset[asset_index],threat_failure_probability_SMT[i],recommended_CDM[threat_failure_probability_SMT[i]])
        print "************************************************* \nFinal Stage"
        print "Total Risk %s" % (gloabl_imposed_risk)
        print "Residual Risk %s" % (recommended_CDM[residual_risk_SMT])
        ############################################## TA ####################################
        print "TA_51_0 %s" % (recommended_CDM[threat_action_security_control_prob_SMT[threat_action_id_to_position_roll[51]][0]])
        print "TA_51_1 %s" % (recommended_CDM[threat_action_security_control_prob_SMT[threat_action_id_to_position_roll[51]][1]])

    print "End time %s" % (time.time() - start_time)

def threat_action_forceable_security_controls(threat_action_list,selected_security_controls_asset,threat_action_id_list_one_asset):
    for threat_action in threat_action_id_list_one_asset:
        threat_action_list[threat_action].clearAssetSpecificList()
        for security_control in threat_action_list[threat_action].applicable_security_controls:
            if security_control in selected_security_controls_asset:
                threat_action_list[threat_action].addAssetSpecificSecurityControl(security_control)

def security_control_asset_threat_action_coverage(threat_action_list,security_control_list,selected_security_controls_asset,threat_action_name_list_asset,asset_index,asset_enterprise_list,risk_threat_action):
    ########################################## Empty applicable threat actions for security controls#########################################################
    # print selected_security_controls_asset
    # print threat_action_name_list_asset
    # print threat_action_id_list_for_all_assets[asset_index]
    for sec_control in selected_security_controls_asset:
        security_control_list[sec_control].clearAllThreatActions()
        for threat_action in security_control_list[sec_control].threat_action:
            if threat_action in threat_action_id_list_for_all_assets[asset_index]:
                security_control_list[sec_control].addAssetThreatAction(threat_action)
    # TestCases.checkThreatActionAssetCoverageSecurityControls(security_control_list,selected_security_controls_asset,asset_index,threat_action_id_list_for_all_assets[asset_index])
    threat_action_forceable_security_controls(threat_action_list,selected_security_controls_asset,threat_action_id_list_for_all_assets[asset_index])
    # TestCases.checkSecurityControlsOfAssetSpecificThreatActions(threat_action_list,threat_action_id_list_for_all_assets[asset_index],asset_enterprise_list[asset_index][0],risk_threat_action[asset_index])

def threat_action_for_threat(threat_list,threat_action_list,threat_name_to_id,asset_index,asset_enterprise_list):
    # Utitilities.printThreat(threat_list,threat_name_to_id)
    for threat in threat_list:
        threat.createAssetThreatAction(threat_action_id_list_for_all_assets[asset_index],asset_enterprise_list[asset_index][0],threat_action_list)
    Utitilities.printThreatObject(threat_list,threat_id_for_all_assets[asset_index],asset_index)

def select_threat(threat_list,asset_enterprise_list):
    for i in range(len(asset_enterprise_list)):
        threat_id_for_all_assets.append([])
    for threat in threat_list:
        for i in range(len(threat.threat_impact_asset)):
            if threat.threat_impact_asset[i] > 0:
                threat_id_for_all_assets[i].append(threat.primary_key)


def startProcessing(security_control_list,selected_security_controls,threat_action_name_list,threat_action_list,asset_enterprise_list,risk_threat_action,threat_list,threat_name_to_id):
    for i in range(len(selected_security_controls)):
        security_control_asset_threat_action_coverage(threat_action_list,security_control_list,selected_security_controls[i],threat_action_name_list[i],i,asset_enterprise_list,risk_threat_action)
    select_threat(threat_list,asset_enterprise_list)
    end_index = len(selected_security_controls)
    for i in range(1,end_index):
        print threat_action_id_list_for_all_assets[i]
        Utitilities.printSecurityControlObject(selected_security_controls[i],security_control_list)
        print selected_security_controls[i]
        Utitilities.printThreatActionObject(threat_action_list,threat_action_id_list_for_all_assets[i],asset_enterprise_list[i][0])
        threat_action_for_threat(threat_list, threat_action_list, threat_name_to_id, i, asset_enterprise_list)
        SMT_Solver(i,security_control_list,threat_action_list,threat_list,asset_enterprise_list)


def select_security_controls(security_control_list,threat_action_list,threat_action_name_to_id,risk_threat_action,asset_enterprise_list,threat_list,threat_name_to_id):
    for threat_action_specific_asset_list in risk_threat_action:
        threat_action_name_list_specific_asset = []
        for threat_action_specific_asset in threat_action_specific_asset_list.keys():
            if threat_action_specific_asset_list[threat_action_specific_asset] > ProjectConfigFile.THREAT_PRIORITIZATION_THRESHOLD:
                ta_index = 0
                for ta in threat_action_name_list_specific_asset:
                    if ta[1] < threat_action_specific_asset_list[threat_action_specific_asset]:
                        break
                    ta_index += 1
                threat_action_name_list_specific_asset.insert(ta_index,[threat_action_name_to_id[threat_action_specific_asset],threat_action_specific_asset_list[threat_action_specific_asset]])
        threat_action_name_list.append(threat_action_name_list_specific_asset)

    for i in range(len(threat_action_name_list)):
        threat_action_id_list_for_all_assets.append([])
        for threat_action_id in threat_action_name_list[i]:
            threat_action_id_list_for_all_assets[i].append(threat_action_id[0])

    for i in range(len(asset_enterprise_list)):
        asset_name = asset_enterprise_list[i][0]
        selected_security_controls_asset = []
        for threat_action in threat_action_name_list[i]:
            for security_control in threat_action_list[threat_action[0]].applicable_security_controls:
                if threat_action[1] < security_control_list[security_control].investment_cost:
                    continue
                if security_control not in selected_security_controls_asset:
                    selected_security_controls_asset.append(security_control)
        selected_security_controls.append(selected_security_controls_asset)
    # Utitilities.printSelectThreatActionName(threat_action_name_list,threat_action_list)
    # Utitilities.printSelectedSecurityControls(security_control_list,selected_security_controls)
    # TestCases.securityControlCoverage(security_control_list,selected_security_controls,threat_action_name_list)
    startProcessing(security_control_list,selected_security_controls,threat_action_name_list,threat_action_list,asset_enterprise_list,risk_threat_action,threat_list,threat_name_to_id)






