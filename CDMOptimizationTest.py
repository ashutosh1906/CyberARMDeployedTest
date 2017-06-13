from z3 import *
def SMT_Environment(security_control_list,selected_security_controls,threat_action_name_list,threat_action_list,
                    threat_action_id_list_for_all_assets,threat_id_for_all_assets,threat_list,asset_enterprise_list):
    print selected_security_controls
    print threat_action_name_list
    print threat_action_id_list_for_all_assets
    print threat_id_for_all_assets

    #########################################  Create the environment for all the selected security controls ##############################
    for asset_index in range(len(selected_security_controls)):
        for sec_control in selected_security_controls[asset_index]:
            security_control_list[sec_control].prepare_global_asset_threat_action_list(threat_action_id_list_for_all_assets)

    print "############################################ Security Controls Properties ########################################################"
    for asset_index in range(len(selected_security_controls)):
        for sec_control in selected_security_controls[asset_index]:
            security_control_list[sec_control].printGlobalAssetThreatActionProperties()

    ########################################## Create the environment for all the threat action #############################################
    for asset_index in range(len(threat_action_id_list_for_all_assets)):
        for threat_action in threat_action_id_list_for_all_assets[asset_index]:
            threat_action_list[threat_action].prepare_global_asset_applicable_security_controls(selected_security_controls)

    print "############################################ Threat Action Properties ########################################################"
    for asset_index in range(len(threat_action_id_list_for_all_assets)):
        for threat_action in threat_action_id_list_for_all_assets[asset_index]:
            threat_action_list[threat_action].printGlobalAssetThreatActionProperties()

    ################################################## Create the environment for threat properties ####################################
    for index in range(len(threat_id_for_all_assets)):
        for threat in threat_id_for_all_assets[index]:
            threat_list[threat].globalCreateAssetThreatAction(threat_action_id_list_for_all_assets,asset_enterprise_list,threat_action_list)

    print "########################################## Threat Properties ########################################################"
    for index in range(len(threat_id_for_all_assets)):
        for threat in threat_id_for_all_assets[index]:
            threat_list[threat].printGlobalProperties()

    ############################################################ Give rank to threat action ##########################################
    threat_action_id_to_position_roll = []
    for index in range(len(threat_id_for_all_assets)):
        threat_action_id_to_position_roll.append({})
        num_threat_action = 0
        for threat_action_id in threat_action_id_list_for_all_assets[index]:
            threat_action_id_to_position_roll[index][threat_action_id] = num_threat_action
            num_threat_action += 1
    print threat_action_id_to_position_roll

    ############################################################ Give rank to threat ##########################################
    threat_id_to_position_roll = []
    for index in range(len(threat_id_for_all_assets)):
        threat_id_to_position_roll.append({})
        num_threat_action = 0
        for threat_id in threat_id_for_all_assets[index]:
            threat_id_to_position_roll[index][threat_id] = num_threat_action
            num_threat_action += 1
    print threat_id_to_position_roll


    ############################################################ Set SMT Environment ####################################################
    set_option(rational_to_decimal=True)
    set_option(precision=30)
    ############################################################ End SMT Environment ####################################################

    ############################################################ Declare SMT Solver #####################################################
    cyberARM = Solver()
    ############################################################ End Declare SMT Solver #################################################

    ############################################################ 1. Declare the variables #################################################
    ############################################################ 1.1 Declare the boolean variables #######################################
    smt_Security_Control_Bool = [[Bool('sec_con_%s_%s' % (i,j)) for j in selected_security_controls[i]] for i in range(len(asset_enterprise_list))]
    print "SMT Security Control Bool %s" %(smt_Security_Control_Bool)

    ############################################################ 1.2 Declare the threat variables #######################################
    smt_Threat = [[Real('Th_%s_%s'%(i,j)) for j in threat_id_for_all_assets[i]] for i in range(len(threat_id_for_all_assets))]
    print "SMT Threat %s" % (smt_Threat)

    ############################################################ 1.3 Declare Threat Action Success Variables#####################################
    smt_Threat_Action_Success = [[Real('t_a_%s_%s'%(i,j)) for j in threat_action_id_list_for_all_assets[i]] for i in range(len(threat_action_id_list_for_all_assets))]
    print "SMT Threat Action Success %s" % (smt_Threat_Action_Success)

    ############################################################ 1.4 Declare Threat Action Security Control Variables ############################
    smt_Threat_Action_Security_Control = [[
        [Real('t_a_s_c_%s_%s_%s'%(i,j,k)) for k in threat_action_list[j].global_asset_applicable_security[i]]
        for j in threat_action_id_list_for_all_assets[i]]
        for i in range(len(threat_action_id_list_for_all_assets))]

    for i in range(len(threat_action_id_list_for_all_assets)):
        print "Threat Action %s: %s"%(i,threat_action_id_list_for_all_assets[i])
        for threat_action_id in threat_action_id_list_for_all_assets[i]:
            print "Threat Action ID %s" % (threat_action_id)
            print "Applicable Security Control %s" % (threat_action_list[threat_action_id].global_asset_applicable_security[i])
            print "SMT Variable %s" % (smt_Threat_Action_Security_Control[i][threat_action_id_to_position_roll[i][threat_action_id]])

    ############################################################ 1.5 Residual Risk Threshold Threat ############################
    smt_Residual_Risk_Asset = [Real('res_risk_asset_%s'%(i[0])) for i in asset_enterprise_list]
    print "Residual Risk Asset %s" % (smt_Residual_Risk_Asset)
    ############################################################ End of Declare the boolean variables #######################################

    ##################################################################### Developing Constraints ############################################
    ##################################################################### 1.1 Threat Action Constraint ######################################
    print "\n**********************************************The main constraints are here ******************************************************************\n"
    for asset_index in range(len(selected_security_controls)):
        print "Selected Sec Controls %s" % (selected_security_controls[asset_index])
        for sec_control in selected_security_controls[asset_index]:
            print "Security Control %s" % (sec_control)
            print "Effectiveness %s" % (security_control_list[sec_control].threat_action_effectiveness)
            print "Threat Action %s" % (security_control_list[sec_control].global_asset_threat_action_list[asset_index])
            for threat_action_id in security_control_list[sec_control].global_asset_threat_action_list[asset_index]:
                print "Threat Action ID %s" % (threat_action_id)
                print "Effectiveness Against Threat Action %s" % (security_control_list[sec_control].threat_action_effectiveness[threat_action_id])
                print smt_Threat_Action_Security_Control[asset_index][threat_action_id_to_position_roll[asset_index][threat_action_id]]
                print "Security Control Position %s" % (threat_action_list[threat_action_id].global_asset_security_control_index[asset_index][sec_control])


    ############################################################ End Declare the variables #################################################
