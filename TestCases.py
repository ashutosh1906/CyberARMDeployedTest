def securityControlCoverage(security_control_list,selected_security_controls,threat_action_name_list):
    threat_action_cover = {}
    index = 0
    for asset in range(len(selected_security_controls)):
        print "\nAsset Name : %s" % (asset)
        threat_action_cover[asset] = []
        for sec_con in selected_security_controls[asset]:
            for cover_ta in security_control_list[sec_con].threat_action:
                if cover_ta not in threat_action_cover[asset]:
                    threat_action_cover[asset].append(cover_ta)
        print sorted(threat_action_cover[asset])
        threat_action_specific = []
        for threat_action in threat_action_name_list[index]:
            threat_action_specific.append(threat_action[0])
        print sorted(threat_action_specific)
        if set(threat_action_cover[asset]) >= set(threat_action_specific):
            print "All threat actions covered for asset : %s" % (asset)
        else:
            print "************** Alarm: All threat actions Not Covered for asset : %s" % (asset)
        index += 1

def checkThreatActionAssetCoverageSecurityControls(security_control_list,selected_security_controls_asset,asset_index,threat_action_id_list_one_asset):
    print "\nAsset Index %s\n" % (asset_index)
    for sec_control in selected_security_controls_asset:
        print "Security Control ID : %s" % (sec_control)
        print "                             Applicable %s " % (security_control_list[sec_control].threat_action)
        print "                             Forceable %s " % (security_control_list[sec_control].asset_threat_action_list)
        if (set(security_control_list[sec_control].asset_threat_action_list) <= set(security_control_list[sec_control].threat_action)) and (set(security_control_list[sec_control].asset_threat_action_list) <= set(threat_action_id_list_one_asset)):
            pass
        else:
            print "****** Alarm : Something Wrong**********************"

def checkSecurityControlsOfAssetSpecificThreatActions(threat_action_list,threat_action_id_list_one_asset,asset_name,risk_threat_action):
    print "<--------------------------------------------------- Asset Name : %s ----------------------------------------------------------------------->"%(asset_name)
    for threat_action_id in threat_action_id_list_one_asset:
        print "\n Threat Action %s\n" % (threat_action_id)
        print "Probability : %s" % (threat_action_list[threat_action_id].prob_given_threat_asset[asset_name])
        print "Risk for this Asset : %s" % (risk_threat_action[threat_action_list[threat_action_id].threat_action_name])
        print "                        ---> Applicable : %s" % (threat_action_list[threat_action_id].applicable_security_controls)
        print "                        ---> Forceable  : %s" % (threat_action_list[threat_action_id].asset_applicable_security_controls)
        print "                        ---> SC Index  : %s" % (threat_action_list[threat_action_id].asset_security_control_index)



