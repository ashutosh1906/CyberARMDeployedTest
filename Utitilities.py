import ProjectConfigFile

def printThreat(threat_list,threat_name_to_id):
    for threat in threat_list:
        print "ID : %s ---> Name : (%s,%s)" % (threat.primary_key,threat.threat_name,threat_name_to_id[threat.threat_name])
        for asset_value in threat.threat_impact_asset:
            print "                 --------> %s" % (asset_value)

def printThreatObject(threat_list,threat_id_for_specific_assets,asset_index):
    print "Asset Index : %s" % (asset_index)
    for threat in threat_id_for_specific_assets:
        threat_list[threat].printProperties()

def printSecurityControlObject(selected_security_controls,security_control_list):
    for sec_id in selected_security_controls:
        security_control_list[sec_id].printProperties()

def printThreatActionObject(threat_action_list,threat_action_id_list_for_specific_assets,asset_name):
    print "******************************************************************* Threat Action ******************************************************************************************"
    for threat_action_id in threat_action_id_list_for_specific_assets:
        threat_action_list[threat_action_id].printProperties(asset_name)

def printSecurityControls(security_control_list,security_control_version_to_id):
    print "***************************** Security Controls ********************************"
    for sec_con in security_control_list:
        print "Primary Key : %s" % (sec_con.primary_key)
        print "Name : %s ## Version : %s"%(sec_con.sc_name,sec_con.sc_version)
        print "%s %s %s" % (sec_con.kc_phase,sec_con.en_level,sec_con.sc_function)
        print " Version : %s to ID ---> %s\n" % (sec_con.sc_version,security_control_version_to_id[sec_con.sc_version])

def printThreatActionList(threat_action_list,threat_action_name_to_id):
    for threat_action in threat_action_list:
        print "Name %s ---------> " % (threat_action.threat_action_name)
        print "Id %s : "%(threat_action.primary_key)
        print "Name: %s to ID : %s" % (threat_action.threat_action_name,threat_action_name_to_id[threat_action.threat_action_name])
        print "Prob given threat against asset "
        for asset in threat_action.prob_given_threat_asset.keys():
            print "  Asset : %s" % (asset)
            print "    Threats : %s\n" % (threat_action.prob_given_threat_asset[asset])

def printKillChainPhases(enterprise_asset_list_given):
    print "All Dimension Description"
    print "Kill Chain Phase ---->"
    print ProjectConfigFile.KILL_CHAIN_PHASE_LIST
    print ProjectConfigFile.KILL_CHAIN_PHASE_TO_ID
    print ProjectConfigFile.ID_TO_KILL_CHAIN_PHASE

    print "Enforcement Level ---->"
    print ProjectConfigFile.ENFORCEMENT_LEVEL_LIST
    print ProjectConfigFile.ENFORCEMENT_LEVEL_TO_ID
    print ProjectConfigFile.ID_TO_ENFORCEMENT_LEVEL

    print "Security Function ---->"
    print ProjectConfigFile.SECURITY_FUNCTION_LIST
    print ProjectConfigFile.SECURITY_FUNCTION_TO_ID
    print ProjectConfigFile.ID_TO_SECURITY_FUNCTION

    print "Asset Unique List ---->"
    print enterprise_asset_list_given

def printRiskThreatThreatAction(risk_threat_action,risk_threat,enterprise_asset_list_given):
    # print risk_threat_action
    # print risk_threat
    for i in range(len(enterprise_asset_list_given)):
        print "Asset Name : %s ----> " % (enterprise_asset_list_given[i])
        print "\n                  Threat ---> "
        for threat in risk_threat[i].keys():
            print "                         %s : %s" % (threat,risk_threat[i][threat])
        print "\n                  Threat Action---> "
        for threat_action in risk_threat_action[i].keys():
            print "                         %s : %s" % (threat_action,risk_threat_action[i][threat_action])



def printThreatImpact():
    print "hacking : %s " % (ProjectConfigFile.HACKING_COST)
    print "malware : %s " % (ProjectConfigFile.MALWARE_COST)
    print "social : %s " % (ProjectConfigFile.MALWARE_COST)
    print "error : %s " % (ProjectConfigFile.MALWARE_COST)
    print "physical : %s " % (ProjectConfigFile.MALWARE_COST)
    print "environmental : %s " % (ProjectConfigFile.MALWARE_COST)
    print "misuse : %s " % (ProjectConfigFile.MALWARE_COST)

def printAllStatistics(prob_threat,threat_threatAction_asset,prob_threat_action_threat,threat_threat_action_possible_pair):
    for threat in threat_threat_action_possible_pair.keys():
        print "___________________________All Possible threat action for this threat _____________________________"
        print threat_threat_action_possible_pair

    for asset in threat_threatAction_asset.keys():
        print "%s -----> "%(asset)
        for threat in threat_threatAction_asset[asset].keys():
            print "<--------  %s -----> " % (threat)
            print "Threat Probability : %s" % (prob_threat[asset][threat])
            print threat_threatAction_asset[asset][threat]
            print prob_threat_action_threat[asset][threat]
            print threat_threat_action_possible_pair[threat]

def printAllStatisticsGivenAssets(prob_threat,threat_threatAction_asset,prob_threat_action_threat,threat_threat_action_possible_pair,enterprise_asset_list_given):
    for threat in threat_threat_action_possible_pair.keys():
        print "___________________________All Possible threat action for this threat _____________________________"
        print threat_threat_action_possible_pair

    for asset in enterprise_asset_list_given:
        print "\n%s -----> \n"%(asset)
        for threat in threat_threatAction_asset[asset].keys():
            print "<--------  %s -----> " % (threat)
            print "Threat Probability : %s" % (prob_threat[asset][threat])
            print threat_threatAction_asset[asset][threat]
            print prob_threat_action_threat[asset][threat]
            print threat_threat_action_possible_pair[threat]


def printThreatThreatActionStatistics(threat_threatAction_asset,prob_threat_threat_action):
    for asset in threat_threatAction_asset.keys():
        print "%s -----> "%(asset)
        for threat_action in prob_threat_threat_action[asset].keys():
            print " %s -----> " % (threat_action)
            for threat in prob_threat_threat_action[asset][threat_action].keys():
                print "    %s -----> " % (threat)
                print "             (%s,%s)" %(threat_threatAction_asset[asset][threat][threat_action],prob_threat_threat_action[asset][threat_action][threat])
    print "Unknown Threat Action %s" % (prob_threat_threat_action[asset][ProjectConfigFile.THREAT_ACTION_UNKNOWN_TAG])


def printNumberStatisticsThreatThreatAction(threat_threatAction_asset):
    for asset in threat_threatAction_asset:
        print "\nAsset Name : %s" % (asset)
        for threat in threat_threatAction_asset[asset].keys():
            print "   Threat : %s ---> %s"%(threat,threat_threatAction_asset[asset][threat])
            if len(threat_threatAction_asset[asset][threat]) ==1 and (ProjectConfigFile.THREAT_ACTION_UNKNOWN_TAG in threat_threatAction_asset[asset][threat].keys()):
                print "************************* Alarm **************************************************************************"

def printNumberStatisticsThreatThreatActionWithProb(prob_threat,threat_threatAction_asset,prob_threat_action_threat):
    for asset in threat_threatAction_asset:
        print "\nAsset Name : %s" % (asset)
        for threat in threat_threatAction_asset[asset].keys():
            print "   Threat : %s ---> %s"%(threat,prob_threat[asset][threat])
            print "                     %s" % (threat_threatAction_asset[asset][threat])
            print "                     %s" % (prob_threat_action_threat[asset][threat])
            if len(threat_threatAction_asset[asset][threat]) ==1 and (ProjectConfigFile.THREAT_ACTION_UNKNOWN_TAG in threat_threatAction_asset[asset][threat].keys()):
                print "************************* Alarm **************************************************************************"

def printSecurityControlThreatmapping(security_control_list,security_control_version_to_id,threat_action_list):
    for sec_control in security_control_list:
        print "\nPrimary Key : %s == ID : %s" % (sec_control.primary_key,security_control_version_to_id[sec_control.sc_version])
        print "Version : %s" % (sec_control.sc_version)
        print "Expense : %s" % (sec_control.investment_cost)
        print "Number of Threat Action : %s" % (sec_control.number_threat_action)
        print "Threat Action --> "
        for i in range(sec_control.number_threat_action):
            print "                    ",
            print "ID : %s --> TA_Name : %s" % (sec_control.threat_action[i],threat_action_list[sec_control.threat_action[i]].threat_action_name)

def printThreatSecurityControlMapping(threat_action_list,threat_action_name_to_id,security_control_list,risk_threat_action,enterprise_asset_list_given):
    zero_security_control = []
    for threat in threat_action_list:
        print "\nPrimary Key : %s === ID : %s" % (threat.primary_key,threat_action_name_to_id[threat.threat_action_name])
        print "Threat Action Name : %s" % (threat.threat_action_name)
        print "Risk Imposed on Asset -->"
        for i in range(len(enterprise_asset_list_given)):
            if threat.threat_action_name not in risk_threat_action[i]:
                continue
            print "                         ",
            print "Asset Name : %s Risk Value : %s " % (
            enterprise_asset_list_given[i], risk_threat_action[i][threat.threat_action_name])
        if len(threat.applicable_security_controls) == 0:
            zero_security_control.append(threat.threat_action_name)
            continue
        print "Security Control -->"
        for i in range(len(threat.applicable_security_controls)):
            print "                         ",
            print "ID : %s ---> Security Control Version : %s %s" % (threat.applicable_security_controls[i],security_control_list[threat.applicable_security_controls[i]].sc_version,threat.security_control_index[threat.applicable_security_controls[i]])


    print "No Security Control Assigned Yet : ---> "
    print zero_security_control

def printSelectThreatActionName(threat_action_name_list,threat_action_list):
    for i in range(len(threat_action_name_list)):
        print "\nAsset ID ----> %s\n" % (i)
        for threat_action in threat_action_name_list[i]:
            print "                                 ",
            print "ID %s : %s ---> Risk Value: %s" %(threat_action[0],threat_action_list[threat_action[0]].threat_action_name,threat_action[1])

def printSelectedSecurityControls(security_control_list,selected_security_controls):
    for asset in range(len(selected_security_controls)):
        print "\nName of the asset ::: %s ------> " % (asset)
        for sec_con in selected_security_controls[asset]:
            print "                              ",
            print "Security Control ID : %s ---> Cost : %s" % (sec_con,security_control_list[sec_con].investment_cost)
        print ""