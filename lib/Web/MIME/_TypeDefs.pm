$Web::MIME::_TypeDefs::Type = {
          '*' => {
                 'subtype' => {
                                '*' => {}
                              }
               },
          'animation' => {
                         'subtype' => {
                                        'narrative' => {}
                                      }
                       },
          'app' => {
                   'subtype' => {
                                  'gg' => {}
                                }
                 },
          'applicaiton' => {
                           'subtype' => {
                                          'x-bytecode.python' => {}
                                        }
                         },
          'application' => {
                           'iana' => 'permanent',
                           'subtype' => {
                                          '1d-interleaved-parityfec' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          '1hz' => {},
                                          '3gpdash-qoe-report+xml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          '3gpp-ims+xml' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'a2l' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'abiword' => {},
                                          'acad' => {},
                                          'access' => {
                                                      'obsolete' => 1
                                                    },
                                          'acrobat' => {},
                                          'activemessage' => {
                                                             'iana' => 'permanent'
                                                           },
                                          'activity+json' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'afp' => {},
                                          'akn+xml' => {
                                                       'iana' => 'provisional'
                                                     },
                                          'album' => {},
                                          'alps+json' => {
                                                         'params' => {
                                                                       'profile' => {}
                                                                     }
                                                       },
                                          'alps+xml' => {
                                                        'params' => {
                                                                      'charset' => {},
                                                                      'profile' => {}
                                                                    },
                                                        'text' => 1
                                                      },
                                          'alto-costmap+json' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'alto-costmapfilter+json' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'alto-directory+json' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'alto-endpointcost+json' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'alto-endpointcostparams+json' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'alto-endpointprop+json' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'alto-endpointpropparams+json' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'alto-error+json' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'alto-networkmap+json' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'alto-networkmapfilter+json' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'aml' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'andrew-inset' => {
                                                            'iana' => 'permanent'
                                                          },
                                          'apis+json' => {},
                                          'appledouble' => {},
                                          'applefile' => {
                                                         'iana' => 'permanent'
                                                       },
                                          'applixware' => {},
                                          'arc' => {},
                                          'arj' => {},
                                          'astound' => {},
                                          'asx' => {},
                                          'atf' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'atfx' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'atom+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common',
                                                        'params' => {
                                                                      'charset' => {},
                                                                      'type' => {}
                                                                    },
                                                        'text' => 1
                                                      },
                                          'atomcat+xml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'atomdeleted+xml' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'atomicmail' => {
                                                          'iana' => 'permanent'
                                                        },
                                          'atomsvc+xml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'atsc-dwd+xml' => {
                                                            'iana' => 'provisional'
                                                          },
                                          'atsc-held+xml' => {
                                                             'iana' => 'provisional'
                                                           },
                                          'attachment' => {},
                                          'atxml' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                          'auth-policy+xml' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'limited use'
                                                             },
                                          'autocad_dwg' => {},
                                          'bacnet-xdd+zip' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'baiducnff-activex' => {},
                                          'base64' => {},
                                          'batch-smtp' => {
                                                          'iana' => 'permanent'
                                                        },
                                          'bdoc' => {},
                                          'beatnik' => {},
                                          'becon-plugin' => {},
                                          'beep+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'limited use'
                                                      },
                                          'ber-stream' => {},
                                          'bgl' => {},
                                          'billboard97' => {},
                                          'binary' => {},
                                          'binhex' => {},
                                          'binhex4' => {},
                                          'bizagi-modeler' => {},
                                          'bld' => {},
                                          'bld2' => {},
                                          'bleeper' => {
                                                       'obsolete' => 1
                                                     },
                                          'bmp' => {},
                                          'book' => {},
                                          'bzip2' => {},
                                          'cab' => {},
                                          'calendar+json' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common',
                                                             'params' => {
                                                                           'component' => {},
                                                                           'method' => {},
                                                                           'optinfo' => {}
                                                                         }
                                                           },
                                          'calendar+xml' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'call-completion' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'limited use'
                                                             },
                                          'cals-1840' => {
                                                         'iana' => 'permanent'
                                                       },
                                          'cals1840' => {
                                                        'obsolete' => 1
                                                      },
                                          'cbor' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'cccex' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                          'ccmp+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'limited use'
                                                      },
                                          'ccv' => {},
                                          'ccxml+xml' => {
                                                         'iana' => 'permanent'
                                                       },
                                          'cdf' => {
                                                   'text' => 1
                                                 },
                                          'cdfx+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'cdmi-capability' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'cdmi-container' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'cdmi-domain' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'cdmi-object' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'cdmi-queue' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'cdni' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'limited use'
                                                  },
                                          'cea' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'cea-2018+xml' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'cellml+xml' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'cfw' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'chromepage' => {},
                                          'clariscad' => {},
                                          'clue_info+xml' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'limited use'
                                                           },
                                          'cms' => {
                                                   'iana' => 'permanent',
                                                   'params' => {
                                                                 'encapsulatingcontent' => {},
                                                                 'innercontent' => {}
                                                               }
                                                 },
                                          'cnrp+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'limited use'
                                                      },
                                          'coap-group+json' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'coap-payload' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'coffee-pot-command' => {
                                                                  'obsolete' => 1,
                                                                  'text' => 1
                                                                },
                                          'commonground' => {
                                                            'iana' => 'permanent'
                                                          },
                                          'compress' => {},
                                          'conference-info+xml' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'core' => {},
                                          'cose' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'cose-key' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'cose-key-set' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'cphl+json' => {},
                                          'cphl+json+code' => {},
                                          'cphl+json+code+formats' => {},
                                          'cphl+json+docs+code+formats' => {},
                                          'cphl+json+formats' => {},
                                          'cphl+xml' => {},
                                          'cphl+xml+docs+code+formats' => {},
                                          'cphl+yaml' => {},
                                          'cphl+yaml+docs+code+formats' => {},
                                          'cpi-download' => {},
                                          'cpi-job' => {},
                                          'cpl+xml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'cprplayer' => {},
                                          'csp-report' => {},
                                          'csrattrs' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'css-stylesheet' => {},
                                          'csta+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'cstadata+xml' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'csv' => {},
                                          'csvm+json' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'cu-seeme' => {},
                                          'cwt' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'cybercash' => {
                                                         'iana' => 'permanent'
                                                       },
                                          'cybermoney' => {},
                                          'dart' => {},
                                          'dase-trigger' => {},
                                          'dash+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common',
                                                        'params' => {
                                                                      'profiles' => {}
                                                                    }
                                                      },
                                          'dashdelta' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'data' => {},
                                          'datawindow' => {},
                                          'davmount+xml' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'db' => {},
                                          'dbase' => {
                                                     'params' => {
                                                                   'version' => {
                                                                                'values' => {
                                                                                            'iv' => {}
                                                                                          }
                                                                              }
                                                                 }
                                                   },
                                          'dbf' => {},
                                          'dca-rft' => {
                                                       'iana' => 'permanent'
                                                     },
                                          'dcd' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'deb' => {},
                                          'dec-dx' => {
                                                      'iana' => 'permanent'
                                                    },
                                          'dec-dx.' => {},
                                          'demonow' => {},
                                          'demonow670' => {},
                                          'demonow750' => {},
                                          'demox' => {},
                                          'demox670' => {},
                                          'demox750' => {},
                                          'deployment' => {},
                                          'dia' => {},
                                          'dialog-info+xml' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'dicom' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                          'dicom+json' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'dicom+rle' => {},
                                          'dicom+xml' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'dii' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'directory' => {},
                                          'directry' => {},
                                          'directx' => {},
                                          'dit' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'dita+xml' => {
                                                        'params' => {
                                                                      'format' => {
                                                                                  'values' => {
                                                                                              'concept' => {},
                                                                                              'map' => {},
                                                                                              'task' => {},
                                                                                              'topic' => {},
                                                                                              'val' => {}
                                                                                            }
                                                                                }
                                                                    }
                                                      },
                                          'dns' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'limited use'
                                                 },
                                          'dns+json' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'dns-message' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'doc' => {},
                                          'docbook+xml' => {},
                                          'docuworks' => {},
                                          'dos-exe' => {},
                                          'download' => {},
                                          'drafting' => {},
                                          'dskpp+xml' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'limited use'
                                                       },
                                          'dsptype' => {},
                                          'dssc+der' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'dssc+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'dsssl' => {},
                                          'dvb.pfr' => {},
                                          'dvbj' => {},
                                          'dvcs' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'dvi' => {},
                                          'dwf' => {
                                                   'params' => {
                                                                 'version' => {
                                                                              'values' => {
                                                                                          '6.0' => {}
                                                                                        }
                                                                            }
                                                               }
                                                 },
                                          'dwg' => {},
                                          'dxf' => {},
                                          'e-score' => {},
                                          'ecmascript' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common',
                                                          'obsolete' => 1,
                                                          'params' => {
                                                                        'charset' => {},
                                                                        'version' => {}
                                                                      },
                                                          'scripting_language' => 'javascript',
                                                          'text' => 1
                                                        },
                                          'ed25519-signature' => {},
                                          'eda.hdl.netlist' => {},
                                          'eda.value_change_dump' => {},
                                          'edi-consent' => {
                                                           'iana' => 'permanent'
                                                         },
                                          'edi-x12' => {
                                                       'iana' => 'permanent'
                                                     },
                                          'edifact' => {
                                                       'iana' => 'permanent'
                                                     },
                                          'editor' => {},
                                          'efi' => {
                                                   'iana' => 'permanent'
                                                 },
                                          'emacs-lisp' => {},
                                          'emergencycalldata.comment+xml' => {
                                                                             'iana' => 'permanent',
                                                                             'iana_intended_usage' => 'limited use'
                                                                           },
                                          'emergencycalldata.control+xml' => {
                                                                             'iana' => 'permanent',
                                                                             'iana_intended_usage' => 'limited use'
                                                                           },
                                          'emergencycalldata.deviceinfo+xml' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'limited use'
                                                                              },
                                          'emergencycalldata.ecall.msd' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'limited use'
                                                                         },
                                          'emergencycalldata.providerinfo+xml' => {
                                                                                  'iana' => 'permanent',
                                                                                  'iana_intended_usage' => 'limited use'
                                                                                },
                                          'emergencycalldata.serviceinfo+xml' => {
                                                                                 'iana' => 'permanent',
                                                                                 'iana_intended_usage' => 'limited use'
                                                                               },
                                          'emergencycalldata.subscriberinfo+xml' => {
                                                                                    'iana' => 'permanent',
                                                                                    'iana_intended_usage' => 'limited use'
                                                                                  },
                                          'emergencycalldata.veds+xml' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'limited use'
                                                                        },
                                          'emf' => {},
                                          'emma+xml' => {
                                                        'iana' => 'permanent'
                                                      },
                                          'emotionml+xml' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'encaprtp' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'limited use'
                                                      },
                                          'envoy' => {},
                                          'eot' => {},
                                          'epp+xml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'eps' => {},
                                          'epub+zip' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'eshop' => {
                                                     'iana' => 'permanent'
                                                   },
                                          'etl' => {},
                                          'example' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'limited use'
                                                     },
                                          'excel' => {
                                                     'obsolete' => 1
                                                   },
                                          'exe' => {},
                                          'exi' => {
                                                   'iana' => 'permanent'
                                                 },
                                          'expect-ct-report+json' => {},
                                          'export' => {},
                                          'f4m' => {},
                                          'fasta' => {},
                                          'fastinfoset' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'fastman' => {},
                                          'fastsoap' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'fdt+xml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'fhir+json' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'fhir+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'fido.trusted-apps+json' => {},
                                          'file-mirror-list' => {},
                                          'filemaker7' => {},
                                          'filenameonly' => {},
                                          'fits' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'flv' => {},
                                          'font-cff' => {},
                                          'font-off' => {},
                                          'font-sfnt' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common',
                                                         'obsolete' => 1
                                                       },
                                          'font-tdpfr' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'font-ttf' => {},
                                          'font-woff' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common',
                                                         'obsolete' => 1
                                                       },
                                          'font-woff2' => {},
                                          'force-download' => {},
                                          'fractals' => {},
                                          'frame-idraw' => {},
                                          'frame-ld+json' => {},
                                          'framemaker' => {},
                                          'framework-attributes+xml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'limited use'
                                                                      },
                                          'freeloader' => {},
                                          'freemind' => {},
                                          'fsharp-script' => {},
                                          'futuresplash' => {
                                                            'obsolete' => 1
                                                          },
                                          'gcwin' => {},
                                          'gdiff' => {},
                                          'geo+json' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'geo+json)' => {},
                                          'geo+json-seq' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'geopackage+sqlite3' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'geoxacml+xml' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'ghostview' => {
                                                         'obsolete' => 1
                                                       },
                                          'gltf-buffer' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'gml+xml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'gnumeric' => {},
                                          'gnutar' => {},
                                          'gopher-ask-block' => {},
                                          'gpx' => {
                                                   'params' => {
                                                                 'charset' => {
                                                                              'charset_xml' => 1
                                                                            }
                                                               },
                                                   'text' => 1
                                                 },
                                          'gpx+xml' => {
                                                       'params' => {
                                                                     'charset' => {
                                                                                  'charset_xml' => 1
                                                                                }
                                                                   },
                                                       'text' => 1
                                                     },
                                          'graph-idraw' => {},
                                          'groupwise' => {},
                                          'gxf' => {},
                                          'gzip' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'gzip-compressed' => {},
                                          'gzipped' => {},
                                          'h224' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'haansofthwp' => {},
                                          'hbbtvcsmanager' => {},
                                          'hdf' => {},
                                          'held+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'limited use'
                                                      },
                                          'hep' => {
                                                   'obsolete' => 1
                                                 },
                                          'hjson' => {},
                                          'hlp' => {},
                                          'hstu' => {},
                                          'hta' => {},
                                          'html-peer-connection-data' => {},
                                          'http' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common',
                                                    'params' => {
                                                                  'msgtype' => {},
                                                                  'version' => {}
                                                                }
                                                  },
                                          'http-content' => {},
                                          'http-credssp-session-encrypted' => {},
                                          'http-index-format' => {},
                                          'http-kerberos-session-encrypted' => {},
                                          'hyperstudio' => {
                                                           'iana' => 'permanent'
                                                         },
                                          'i-deas' => {},
                                          'ibe-key-request+xml' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'ibe-pkg-reply+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'ibe-pp-data' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'ichitaro4' => {},
                                          'ichitaro5' => {},
                                          'ichitaro6' => {},
                                          'ico' => {},
                                          'idp' => {},
                                          'ie' => {},
                                          'iges' => {
                                                    'iana' => 'permanent'
                                                  },
                                          'illustrator' => {},
                                          'im-iscomposing+xml' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'limited use'
                                                                },
                                          'imagemap' => {
                                                        'obsolete' => 1
                                                      },
                                          'imagenation' => {},
                                          'index' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'limited use'
                                                   },
                                          'index.cmd' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'limited use'
                                                       },
                                          'index.cmd.datachanged' => {},
                                          'index.cmd.noop' => {},
                                          'index.cmd.poll' => {},
                                          'index.obj' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'limited use'
                                                       },
                                          'index.response' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use'
                                                            },
                                          'index.vnd' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'limited use'
                                                       },
                                          'inf' => {},
                                          'inkml+xml' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'internet-property-stream' => {},
                                          'internet-shortcut' => {},
                                          'ion' => {
                                                   'iana' => 'provisional'
                                                 },
                                          'iotp' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'ipfix' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'limited use'
                                                   },
                                          'ipp' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'isup' => {
                                                    'iana' => 'permanent'
                                                  },
                                          'isys' => {},
                                          'its+xml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'itunes' => {},
                                          'itunes-plugin' => {},
                                          'java' => {},
                                          'java-archive' => {},
                                          'java-byte-code' => {},
                                          'java-deployment-toolkit' => {},
                                          'java-serialized-object' => {},
                                          'java-vm' => {},
                                          'javascript' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common',
                                                          'obsolete' => 1,
                                                          'params' => {
                                                                        'charset' => {},
                                                                        'version' => {}
                                                                      },
                                                          'scripting_language' => 'javascript',
                                                          'text' => 1
                                                        },
                                          'javatv-xlet' => {},
                                          'jb64' => {},
                                          'jf2feed+json' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'jnlp' => {},
                                          'jose' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'jose+json' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'jpg' => {},
                                          'jrd+json' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'jsgf' => {},
                                          'json' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common',
                                                    'params' => {
                                                                  'charset' => {},
                                                                  'ieee754compatible' => {},
                                                                  'odata' => {},
                                                                  'odata.metadata' => {},
                                                                  'odata.streaming' => {},
                                                                  'profile' => {}
                                                                },
                                                    'text' => 1
                                                  },
                                          'json+ld' => {},
                                          'json+n3' => {},
                                          'json+ntriples' => {},
                                          'json+oembed' => {},
                                          'json+protobuf' => {},
                                          'json+rdf' => {},
                                          'json+rdf+xml' => {},
                                          'json+turtle' => {},
                                          'json-object' => {},
                                          'json-patch+json' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'json-seq' => {
                                                        'iana' => 'permanent'
                                                      },
                                          'json5' => {},
                                          'jsonml+json' => {},
                                          'juttle' => {},
                                          'jwc' => {},
                                          'jwk+json' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'jwk-set+json' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'jwt' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'jxw' => {},
                                          'kal' => {},
                                          'kate' => {},
                                          'keychain_access' => {},
                                          'kit' => {},
                                          'kpml-request+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'kpml-response+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'latex' => {},
                                          'ld+json' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common',
                                                       'params' => {
                                                                     'profile' => {}
                                                                   }
                                                     },
                                          'ldesc+xml' => {
                                                         'params' => {
                                                                       'profile' => {}
                                                                     }
                                                       },
                                          'ldjson' => {},
                                          'lgh' => {},
                                          'lgr+xml' => {
                                                       'iana' => 'permanent'
                                                     },
                                          'lha' => {},
                                          'lightwright' => {},
                                          'link-format' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'liquidmotion' => {},
                                          'listenup' => {},
                                          'load-control+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'logml' => {},
                                          'lolcat' => {},
                                          'lost+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'limited use'
                                                      },
                                          'lostsync+xml' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'lotus' => {},
                                          'lotus-123' => {
                                                         'obsolete' => 1
                                                       },
                                          'lotus123' => {
                                                        'params' => {
                                                                      'version' => {
                                                                                   'values' => {
                                                                                               '3.0' => {},
                                                                                               '4-5' => {}
                                                                                             }
                                                                                 }
                                                                    }
                                                      },
                                          'lwp' => {
                                                   'params' => {
                                                                 'version' => {
                                                                              'values' => {
                                                                                          '96' => {},
                                                                                          '97/millennium' => {}
                                                                                        }
                                                                            }
                                                               }
                                                 },
                                          'lxf' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'lyx' => {},
                                          'lzh' => {},
                                          'lzx' => {},
                                          'mac-binary' => {},
                                          'mac-binhex' => {},
                                          'mac-binhex40' => {
                                                            'iana' => 'permanent'
                                                          },
                                          'mac-compactpro' => {
                                                              'obsolete' => 1
                                                            },
                                          'macbinary' => {},
                                          'macwriteii' => {
                                                          'iana' => 'permanent'
                                                        },
                                          'mads+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'maker' => {},
                                          'manifest' => {},
                                          'manifest+json' => {},
                                          'maple-v-r4' => {},
                                          'marc' => {
                                                    'iana' => 'permanent'
                                                  },
                                          'marc+xml' => {},
                                          'marche' => {},
                                          'marcxml+xml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'marimba' => {},
                                          'mathcad' => {
                                                       'obsolete' => 1
                                                     },
                                          'mathematica' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'mathematica-old' => {
                                                               'obsolete' => 1
                                                             },
                                          'mathmatica' => {},
                                          'mathml+xml' => {
                                                          'iana' => 'permanent',
                                                          'params' => {
                                                                        'charset' => {}
                                                                      },
                                                          'text' => 1
                                                        },
                                          'mathml-content+xml' => {
                                                                  'iana' => 'permanent'
                                                                },
                                          'mathml-presentation+xml' => {
                                                                       'iana' => 'permanent'
                                                                     },
                                          'matlab-mat' => {},
                                          'mbedlet' => {},
                                          'mbms-associated-procedure-description+xml' => {
                                                                                         'iana' => 'permanent',
                                                                                         'iana_intended_usage' => 'common'
                                                                                       },
                                          'mbms-deregister+xml' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'mbms-envelope+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'mbms-msk+xml' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'mbms-msk-response+xml' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'mbms-protection-description+xml' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'mbms-reception-report+xml' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'mbms-register+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'mbms-register-response+xml' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'mbms-schedule+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'mbms-user-service-description+xml' => {
                                                                                 'iana' => 'permanent',
                                                                                 'iana_intended_usage' => 'common'
                                                                               },
                                          'mbox' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common',
                                                    'params' => {
                                                                  'format' => {}
                                                                },
                                                    'text' => 1
                                                  },
                                          'mcad' => {},
                                          'mdb' => {},
                                          'media-policy-dataset+xml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'media_control+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'mediaservercontrol+xml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'merge-patch+json' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'metalink+xml' => {},
                                          'metalink4+xml' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'metastream' => {},
                                          'mets+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'mf4' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'micro3d' => {},
                                          'microdata+bibtex' => {},
                                          'microdata+json' => {},
                                          'mikey' => {
                                                     'iana' => 'permanent'
                                                   },
                                          'mime' => {},
                                          'mmt-aei+xml' => {
                                                           'iana' => 'provisional'
                                                         },
                                          'mmt-usd+xml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'mods+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'moss-keys' => {
                                                         'iana' => 'permanent'
                                                       },
                                          'moss-signature' => {
                                                              'iana' => 'permanent'
                                                            },
                                          'mosskey-data' => {
                                                            'iana' => 'permanent'
                                                          },
                                          'mosskey-request' => {
                                                               'iana' => 'permanent'
                                                             },
                                          'mp21' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'mp4' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'mpeg4' => {},
                                          'mpeg4-generic' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'mpeg4-iod' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'mpeg4-iod-xmt' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'mpeg4-muxcodetable' => {},
                                          'mpp' => {},
                                          'mrb-consumer+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'mrb-publish+xml' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'ms-access' => {},
                                          'ms-download' => {},
                                          'ms-excel' => {},
                                          'ms-java' => {},
                                          'ms-powerpoint' => {},
                                          'ms-tnef' => {},
                                          'ms-vsi' => {},
                                          'ms-word' => {},
                                          'msaccess' => {},
                                          'msaccess.addin' => {},
                                          'msaccess.cab' => {},
                                          'msaccess.ftemplate' => {},
                                          'msaccess.runtime' => {},
                                          'msaccess.webapplication' => {},
                                          'msc-ivr+xml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'limited use'
                                                         },
                                          'msc-mixer+xml' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'limited use'
                                                           },
                                          'msdos-windows' => {},
                                          'msdownload' => {},
                                          'msexcel' => {},
                                          'msexcell' => {},
                                          'msi' => {},
                                          'msonenote' => {},
                                          'mspowerpoint' => {},
                                          'msppt' => {},
                                          'msproj' => {},
                                          'msproject' => {},
                                          'msword' => {
                                                      'iana' => 'permanent',
                                                      'params' => {
                                                                    'version' => {
                                                                                 'values' => {
                                                                                             '1.0' => {},
                                                                                             '2.0' => {},
                                                                                             '3.0' => {},
                                                                                             '4.0' => {},
                                                                                             '5.0' => {},
                                                                                             '5.5' => {},
                                                                                             '6.0-2003' => {},
                                                                                             '6.0/95' => {},
                                                                                             '97-2003' => {},
                                                                                             'x' => {}
                                                                                           }
                                                                               }
                                                                  }
                                                    },
                                          'msword-doc' => {},
                                          'msword2' => {},
                                          'msword5' => {},
                                          'msworks' => {},
                                          'mswrite' => {},
                                          'mud+json' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'mxf' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'n-quads' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'n-triples' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'n3' => {},
                                          'name' => {},
                                          'naplps' => {},
                                          'naplps-audio' => {},
                                          'nappdf' => {},
                                          'nasdata' => {
                                                       'iana' => 'permanent'
                                                     },
                                          'netcdf' => {},
                                          'netmc' => {},
                                          'netobject' => {},
                                          'news-checkgroups' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'news-groupinfo' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'news-message-id' => {
                                                               'obsolete' => 1
                                                             },
                                          'news-transmission' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common',
                                                                 'params' => {
                                                                               'conversions' => {},
                                                                               'usage' => {}
                                                                             },
                                                                 'text' => 1
                                                               },
                                          'nlsml+xml' => {
                                                         'iana' => 'permanent'
                                                       },
                                          'node' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'npsigncap' => {},
                                          'nss' => {
                                                   'iana' => 'permanent'
                                                 },
                                          'ntriples' => {},
                                          'oasis' => {},
                                          'ocsp-request' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'ocsp-response' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'oct-stream' => {},
                                          'octaga' => {},
                                          'octagaplayer' => {},
                                          'octect-stream' => {},
                                          'octet' => {},
                                          'octet-stream' => {
                                                            'iana' => 'permanent',
                                                            'params' => {
                                                                          'conversions' => {},
                                                                          'name' => {},
                                                                          'padding' => {},
                                                                          'type' => {},
                                                                          'version' => {
                                                                                       'values' => {
                                                                                                   '4' => {},
                                                                                                   '5' => {},
                                                                                                   'generic' => {}
                                                                                                 }
                                                                                     },
                                                                          'x-conversions' => {}
                                                                        },
                                                            'scripting_language' => 'no'
                                                          },
                                          'octet-string' => {},
                                          'octetstream' => {},
                                          'oda' => {
                                                   'iana' => 'permanent'
                                                 },
                                          'odx' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'oebps-package+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'ogg' => {
                                                   'audiovideo' => 1,
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'oipfcapabilities' => {},
                                          'oleobject' => {},
                                          'olescript' => {},
                                          'omdoc+xml' => {},
                                          'onenote' => {},
                                          'opensearchdescription+xml' => {},
                                          'openservicedescription+xml' => {},
                                          'openstack-images-v2.0-json-patch' => {},
                                          'openstack-images-v2.1-json-patch' => {},
                                          'opentype' => {},
                                          'opf' => {},
                                          'orchestrate-export+json' => {},
                                          'orchestrate-export-stream+json' => {},
                                          'otf' => {},
                                          'other' => {},
                                          'ov-idraw' => {},
                                          'oxps' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'p2p-overlay+xml' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'package' => {},
                                          'parityfec' => {
                                                         'iana' => 'permanent'
                                                       },
                                          'passport' => {
                                                        'iana' => 'permanent'
                                                      },
                                          'patch-ops-error+xml' => {
                                                                   'iana' => 'permanent'
                                                                 },
                                          'pbautomation' => {},
                                          'pbld' => {},
                                          'pdf' => {
                                                   'iana' => 'permanent',
                                                   'params' => {
                                                                 'version' => {
                                                                              'values' => {
                                                                                          '1.0' => {},
                                                                                          '1.1' => {},
                                                                                          '1.2' => {},
                                                                                          '1.3' => {},
                                                                                          '1.4' => {},
                                                                                          '1.5' => {},
                                                                                          '1.6' => {},
                                                                                          '1.7' => {},
                                                                                          '1a' => {},
                                                                                          '1b' => {},
                                                                                          '2a' => {},
                                                                                          '2b' => {},
                                                                                          '2u' => {},
                                                                                          '3a' => {},
                                                                                          '3b' => {},
                                                                                          '3u' => {}
                                                                                        }
                                                                            }
                                                               }
                                                 },
                                          'pdx' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'pert.chart+xml' => {},
                                          'pgp' => {
                                                   'params' => {
                                                                 'charset' => {}
                                                               },
                                                   'text' => 1
                                                 },
                                          'pgp-encrypted' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'pgp-keys' => {
                                                        'iana' => 'permanent'
                                                      },
                                          'pgp-signature' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common',
                                                             'text' => 1
                                                           },
                                          'photobubble' => {},
                                          'photoshop' => {},
                                          'php' => {},
                                          'pics-labels' => {},
                                          'pics-rules' => {},
                                          'pics-service' => {},
                                          'pidf+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'limited use'
                                                      },
                                          'pidf-diff+xml' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'limited use'
                                                           },
                                          'pkcs-12' => {},
                                          'pkcs-crl' => {},
                                          'pkcs10' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                          'pkcs12' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                          'pkcs7-mime' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'pkcs7-signature' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'pkcs8' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                          'pkcs8-encrypted' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'pkix-attr-cert' => {
                                                              'iana' => 'permanent'
                                                            },
                                          'pkix-cert' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common',
                                                         'params' => {
                                                                       'version' => {
                                                                                    '#obsolete' => 1
                                                                                  }
                                                                     }
                                                       },
                                          'pkix-crl' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common',
                                                        'params' => {
                                                                      'version' => {
                                                                                   '#obsolete' => 1
                                                                                 }
                                                                    }
                                                      },
                                          'pkix-pkipath' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common',
                                                            'params' => {
                                                                          'version' => {}
                                                                        }
                                                          },
                                          'pkixcmp' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'plain' => {},
                                          'playerpro' => {},
                                          'pls+xml' => {
                                                       'iana' => 'permanent'
                                                     },
                                          'poc-settings+xml' => {
                                                                'iana' => 'permanent'
                                                              },
                                          'postscript' => {
                                                          'iana' => 'permanent',
                                                          'params' => {
                                                                        'version' => {
                                                                                     'values' => {
                                                                                                 '1.0' => {},
                                                                                                 '1.0 / 1.1' => {},
                                                                                                 '1.2' => {},
                                                                                                 '2.0' => {},
                                                                                                 '2.1' => {},
                                                                                                 '3' => {},
                                                                                                 '3.0' => {}
                                                                                               }
                                                                                   }
                                                                      }
                                                        },
                                          'pot' => {},
                                          'powerpoint' => {},
                                          'powershell' => {},
                                          'ppm' => {},
                                          'pps' => {},
                                          'ppsp-tracker+json' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'ppt' => {},
                                          'pre-encrypted' => {},
                                          'presentations' => {},
                                          'pro_eng' => {},
                                          'problem+json' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'problem+xml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'protobuf' => {},
                                          'provenance+xml' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'prs.alvestrand.titrax-sheet' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'limited use'
                                                                         },
                                          'prs.cww' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'prs.hpub+zip' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'prs.nprend' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'prs.plucker' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'prs.rdf-xml-crypt' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'prs.xsf+xml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'psd' => {},
                                          'pskc+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'limited use'
                                                      },
                                          'ptg-file' => {},
                                          'qif' => {},
                                          'qsig' => {
                                                    'iana' => 'permanent'
                                                  },
                                          'quattro-pro' => {},
                                          'quicktimeplayer' => {
                                                               'obsolete' => 1
                                                             },
                                          'ram' => {},
                                          'raml+yaml' => {},
                                          'raptorfec' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'rar' => {},
                                          'rat-file' => {},
                                          'rdap+json' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'rdf+json' => {},
                                          'rdf+n3' => {},
                                          'rdf+thrift' => {},
                                          'rdf+xml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common',
                                                       'params' => {
                                                                     'charset' => {}
                                                                   },
                                                       'text' => 1
                                                     },
                                          'reginfo+xml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'relax-ng-compact-syntax' => {
                                                                       'iana' => 'permanent'
                                                                     },
                                          'remote-printing' => {
                                                               'iana' => 'permanent'
                                                             },
                                          'remote_printing' => {
                                                               'obsolete' => 1
                                                             },
                                          'report' => {},
                                          'reports+json' => {
                                                            'iana' => 'provisional'
                                                          },
                                          'reputon+json' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'resedit' => {},
                                          'resource-lists+xml' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'resource-lists-diff+xml' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'rfc+xml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'richtext' => {},
                                          'ringing-tones' => {},
                                          'riscos' => {
                                                      'iana' => 'permanent'
                                                    },
                                          'rlmi+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'limited use'
                                                      },
                                          'rls-services+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'route-apd+xml' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'route-s-tsid+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'route-usd+xml' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'rpki-ghostbusters' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'rpki-manifest' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'rpki-publication' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'rpki-roa' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'rpki-updown' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'rpm' => {},
                                          'rsd+xml' => {},
                                          'rss+xml' => {
                                                       'params' => {
                                                                     'charset' => {}
                                                                   },
                                                       'text' => 1
                                                     },
                                          'rtf' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common',
                                                   'params' => {
                                                                 'version' => {
                                                                              'values' => {
                                                                                          '1.0-1.4' => {},
                                                                                          '1.1' => {},
                                                                                          '1.2' => {},
                                                                                          '1.3' => {},
                                                                                          '1.4' => {},
                                                                                          '1.5-1.6' => {},
                                                                                          '1.6' => {},
                                                                                          '1.7' => {},
                                                                                          '1.8' => {},
                                                                                          '1.9' => {}
                                                                                        }
                                                                            }
                                                               }
                                                 },
                                          'rtploopback' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'limited use'
                                                         },
                                          'rtx' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          's-http' => {},
                                          'samlassertion+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'samlmetadata+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'sas' => {},
                                          'save' => {},
                                          'save-as' => {},
                                          'sbml+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'limited use'
                                                      },
                                          'scaip+xml' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'limited use'
                                                       },
                                          'schema+json' => {},
                                          'scim+json' => {
                                                         'iana' => 'permanent'
                                                       },
                                          'scvp-cv-request' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'scvp-cv-response' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'scvp-vp-request' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'scvp-vp-response' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'sdp' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'sea' => {},
                                          'secevent+jwt' => {
                                                            'iana' => 'permanent'
                                                          },
                                          'senml+cbor' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'senml+json' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'senml+xml' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'senml-exi' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'sensml+cbor' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'sensml+json' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'sensml+xml' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'sensml-exi' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'sep+xml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'sep-exi' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'sereal' => {
                                                      'params' => {
                                                                    'version' => {
                                                                                 'values' => {
                                                                                             '1' => {},
                                                                                             '2' => {},
                                                                                             '3' => {}
                                                                                           }
                                                                               }
                                                                  }
                                                    },
                                          'session-info' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'set' => {},
                                          'set-payment' => {
                                                           'iana' => 'permanent'
                                                         },
                                          'set-payment-initiation' => {
                                                                      'iana' => 'permanent'
                                                                    },
                                          'set-registration' => {
                                                                'iana' => 'permanent'
                                                              },
                                          'set-registration-initiation' => {
                                                                           'iana' => 'permanent'
                                                                         },
                                          'sgml' => {
                                                    'iana' => 'permanent',
                                                    'params' => {
                                                                  'sgml-bctf' => {},
                                                                  'sgml-boot' => {}
                                                                },
                                                    'text' => 1
                                                  },
                                          'sgml-form-urlencoded' => {
                                                                    'obsolete' => 1,
                                                                    'text' => 1
                                                                  },
                                          'sgml-open-catalog' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use',
                                                                 'params' => {
                                                                               'charset' => {}
                                                                             },
                                                                 'text' => 1
                                                               },
                                          'shf+xml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'sieve' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                          'simple-filter+xml' => {
                                                                 'iana' => 'permanent'
                                                               },
                                          'simple-message-summary' => {
                                                                      'iana' => 'permanent'
                                                                    },
                                          'simplesymbolcontainer' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'sit' => {},
                                          'sla' => {},
                                          'slate' => {
                                                     'iana' => 'permanent'
                                                   },
                                          'sld' => {},
                                          'slddrw' => {},
                                          'sldprt' => {},
                                          'sldworks' => {},
                                          'smil' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'obsolete',
                                                    'obsolete' => 1,
                                                    'params' => {
                                                                  'charset' => {},
                                                                  'profile' => {}
                                                                },
                                                    'text' => 1
                                                  },
                                          'smil+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common',
                                                        'params' => {
                                                                      'charset' => {},
                                                                      'profile' => {}
                                                                    },
                                                        'text' => 1
                                                      },
                                          'smpte336m' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'sns' => {},
                                          'soap+fastinfoset' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'soap+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'softgrid-doc' => {},
                                          'softgrid-java' => {},
                                          'softvision' => {},
                                          'solids' => {},
                                          'soundapp' => {},
                                          'sounder' => {},
                                          'sparql-query' => {
                                                            'iana' => 'permanent'
                                                          },
                                          'sparql-results+thrift' => {},
                                          'sparql-results+xml' => {
                                                                  'iana' => 'permanent'
                                                                },
                                          'spirits-event+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'spss' => {},
                                          'sql' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                          'srgs' => {
                                                    'iana' => 'permanent'
                                                  },
                                          'srgs+xml' => {
                                                        'iana' => 'permanent'
                                                      },
                                          'sru+xml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'ssdl+xml' => {},
                                          'ssml+xml' => {
                                                        'iana' => 'permanent'
                                                      },
                                          'step' => {},
                                          'stix+json' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'stream+json' => {},
                                          'streamingmedia' => {},
                                          'studiom' => {},
                                          'stuffit' => {},
                                          'stuffitx' => {},
                                          'supercollider' => {},
                                          't-time' => {},
                                          'tamp-apex-update' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'limited use'
                                                              },
                                          'tamp-apex-update-confirm' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'limited use'
                                                                      },
                                          'tamp-community-update' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'limited use'
                                                                   },
                                          'tamp-community-update-confirm' => {
                                                                             'iana' => 'permanent',
                                                                             'iana_intended_usage' => 'limited use'
                                                                           },
                                          'tamp-error' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'limited use'
                                                        },
                                          'tamp-sequence-adjust' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'tamp-sequence-adjust-confirm' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'limited use'
                                                                          },
                                          'tamp-status-query' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'tamp-status-response' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'tamp-update' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'limited use'
                                                         },
                                          'tamp-update-confirm' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'limited use'
                                                                 },
                                          'tar' => {},
                                          'taxii+json' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'tei+xml' => {
                                                       'iana' => 'permanent'
                                                     },
                                          'testfontstream' => {},
                                          'tetra_isi' => {
                                                         'iana' => 'provisional'
                                                       },
                                          'tex' => {},
                                          'texinfo' => {},
                                          'text' => {},
                                          'tga' => {},
                                          'thraud+xml' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'limited use'
                                                        },
                                          'tif' => {},
                                          'tiff' => {},
                                          'timbuktu' => {},
                                          'timestamp-query' => {
                                                               'iana' => 'permanent'
                                                             },
                                          'timestamp-reply' => {
                                                               'iana' => 'permanent'
                                                             },
                                          'timestamped-data' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'tlsrpt+gzip' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'tlsrpt+json' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'tnauthlist' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'tnt' => {},
                                          'tntfile' => {},
                                          'toc' => {},
                                          'toolbook' => {
                                                        'obsolete' => 1
                                                      },
                                          'trickle-ice-sdpfrag' => {
                                                                   'iana' => 'permanent'
                                                                 },
                                          'trig' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'truetype' => {},
                                          'ttf' => {},
                                          'ttml+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common',
                                                        'params' => {
                                                                      'charset' => {},
                                                                      'codecs' => {},
                                                                      'profile' => {}
                                                                    },
                                                        'text' => 1
                                                      },
                                          'turtle' => {},
                                          'tve-trigger' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'twb' => {},
                                          'twbx' => {},
                                          'typescript' => {},
                                          'ubjson' => {},
                                          'ulpfec' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                          'unknown' => {},
                                          'urc-grpsheet+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'urc-ressheet+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'urc-targetdesc+xml' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'urc-uisocketdesc+xml' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'uue' => {},
                                          'uuencode' => {},
                                          'uwi_bin' => {},
                                          'uwi_form' => {},
                                          'uwi_nothing' => {},
                                          'vcard+json' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common',
                                                          'params' => {
                                                                        'version' => {}
                                                                      }
                                                        },
                                          'vcard+xml' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'vda' => {},
                                          'vemmi' => {
                                                     'iana' => 'permanent'
                                                   },
                                          'vis5d' => {},
                                          'visio' => {},
                                          'visio.drawing' => {},
                                          'vividence.scriptfile' => {},
                                          'vml+xml' => {},
                                          'vmsbackup' => {
                                                         'obsolete' => 1
                                                       },
                                          'vnd' => {},
                                          'vnd-garmin.mygarmin' => {},
                                          'vnd-koan' => {},
                                          'vnd-ms-excel' => {},
                                          'vnd-mspowerpoint' => {},
                                          'vnd.1000minds.decision-model+xml' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'common'
                                                                              },
                                          'vnd.3gpp-prose+xml' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.3gpp-prose-pc3ch+xml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.3gpp-v2x-local-service-information' => {
                                                                                      'iana' => 'permanent',
                                                                                      'iana_intended_usage' => 'common'
                                                                                    },
                                          'vnd.3gpp.access-transfer-events+xml' => {
                                                                                   'iana' => 'permanent',
                                                                                   'iana_intended_usage' => 'common'
                                                                                 },
                                          'vnd.3gpp.bsf+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.3gpp.gmop+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.3gpp.mc-signalling-ear' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.3gpp.mcdata-payload' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.3gpp.mcdata-signalling' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.3gpp.mcptt-affiliation-command+xml' => {
                                                                                      'iana' => 'permanent',
                                                                                      'iana_intended_usage' => 'common'
                                                                                    },
                                          'vnd.3gpp.mcptt-floor-request+xml' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'common'
                                                                              },
                                          'vnd.3gpp.mcptt-info+xml' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.3gpp.mcptt-location-info+xml' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'common'
                                                                              },
                                          'vnd.3gpp.mcptt-mbms-usage-info+xml' => {
                                                                                  'iana' => 'permanent',
                                                                                  'iana_intended_usage' => 'common'
                                                                                },
                                          'vnd.3gpp.mcptt-signed+xml' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.3gpp.mid-call+xml' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.3gpp.pic-bw-large' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.3gpp.pic-bw-small' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.3gpp.pic-bw-var' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.3gpp.sms' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.3gpp.sms+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.3gpp.srvcc-ext+xml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.3gpp.srvcc-info+xml' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.3gpp.state-and-event-info+xml' => {
                                                                                 'iana' => 'permanent',
                                                                                 'iana_intended_usage' => 'common'
                                                                               },
                                          'vnd.3gpp.ussd+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.3gpp2.bcmcsinfo+xml' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.3gpp2.sms' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.3gpp2.tcap' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.3lightssoftware.imagescal' => {
                                                                             'iana' => 'permanent',
                                                                             'iana_intended_usage' => 'limited use'
                                                                           },
                                          'vnd.3m.post-it-notes' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.accpac.simply.aso' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'limited use'
                                                                   },
                                          'vnd.accpac.simply.imp' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'limited use'
                                                                   },
                                          'vnd.acucobol' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.acucorp' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.adobe.aftereffects.project' => {},
                                          'vnd.adobe.aftereffects.template' => {},
                                          'vnd.adobe.air-application-installer-package+zip' => {},
                                          'vnd.adobe.assest-catalog' => {},
                                          'vnd.adobe.edn' => {},
                                          'vnd.adobe.fla' => {},
                                          'vnd.adobe.flash.movie' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.adobe.formscentral.fcdt' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                          'vnd.adobe.fxp' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.adobe.illustrator' => {},
                                          'vnd.adobe.indesign-idml-package' => {},
                                          'vnd.adobe.partial-upload' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'limited use'
                                                                      },
                                          'vnd.adobe.pdfxml' => {},
                                          'vnd.adobe.pdx' => {},
                                          'vnd.adobe.photoshop' => {},
                                          'vnd.adobe.rmf' => {},
                                          'vnd.adobe.x-mars' => {},
                                          'vnd.adobe.xdp+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.adobe.xfd+xml' => {},
                                          'vnd.adobe.xfdf' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.aether.imp' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.afpc.afplinedata' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'vnd.afpc.modca' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use'
                                                            },
                                          'vnd.ah-barcode' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'obsolete',
                                                              'obsolete' => 1
                                                            },
                                          'vnd.ahead.space' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.airzip.filesecure.azf' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.airzip.filesecure.azs' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.altera.quartus.internal' => {},
                                          'vnd.altera.quartus.project_file' => {},
                                          'vnd.altera.quartus.settings_file' => {},
                                          'vnd.am+xml' => {},
                                          'vnd.amadeus+json' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'limited use'
                                                              },
                                          'vnd.amazon.ebook' => {},
                                          'vnd.amazon.mobi8-ebook' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.americandynamics.acc' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'limited use'
                                                                      },
                                          'vnd.amiga.ami' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.amiga.amu' => {},
                                          'vnd.amundsen.maze+xml' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.android.package-archive' => {},
                                          'vnd.anki' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.anser-web-certificate-issue-initiation' => {
                                                                                          'iana' => 'permanent',
                                                                                          'iana_intended_usage' => 'common'
                                                                                        },
                                          'vnd.anser-web-funds-transfer-initiation' => {},
                                          'vnd.antix.game-component' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.apache.thrift.binary' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.apache.thrift.compact' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.apache.thrift.json' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.api+json' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.apothekende.reservation+json' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'common'
                                                                              },
                                          'vnd.apple.installer+xml' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.apple.iwork' => {},
                                          'vnd.apple.keynote' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.apple.mpegurl' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'vnd.apple.numbers' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.apple.pages' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.apple.pkpass' => {},
                                          'vnd.arastra.swi' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'obsolete',
                                                               'obsolete' => 1
                                                             },
                                          'vnd.aristanetworks.swi' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.artgalry' => {},
                                          'vnd.artisan+json' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.artsquare' => {
                                                             'iana' => 'permanent'
                                                           },
                                          'vnd.astraea-software.iota' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.audiograph' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.autopackage' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.avalon+json' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.avistar+xml' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'limited use'
                                                             },
                                          'vnd.balsamiq.bmml+xml' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.balsamiq.bmpr' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.banana-accounting' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.bbf.usp.msg' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.bbf.usp.msg+json' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'vnd.bekitzur-stech+json' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.bint.med-content' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'vnd.biopax.rdf+xml' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.blink-idb-value-wrapper' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'limited use'
                                                                         },
                                          'vnd.blueice.multipass' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.bluetooth.ep.oob' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.bluetooth.le.oob' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.bmi' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.businessobjects' => {
                                                                   'iana' => 'permanent'
                                                                 },
                                          'vnd.bw-fontobject' => {},
                                          'vnd.bw-fontobject-b7' => {},
                                          'vnd.bw-fontobject-b8' => {},
                                          'vnd.byu.uapi+json' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.cab-jscript' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.canon-cpdl' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.canon-lips' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.capasystems-pg+json' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'limited use'
                                                                     },
                                          'vnd.cendio.thinlinc.clientconf' => {
                                                                              'iana' => 'permanent',
                                                                              'iana_intended_usage' => 'limited use'
                                                                            },
                                          'vnd.century-systems.tcp_stream' => {
                                                                              'iana' => 'permanent',
                                                                              'iana_intended_usage' => 'common'
                                                                            },
                                          'vnd.chemdraw+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.chess-pgn' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.chipnuts.karaoke-mmd' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.chromium.remoting-viewer' => {},
                                          'vnd.cinderella' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.cirpack.isdn-ext' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'vnd.citationstyles.style+xml' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.claymore' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.cloanto.rp9' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.clonk.c4group' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'vnd.cluetrust.cartomobile-config' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'limited use'
                                                                              },
                                          'vnd.cluetrust.cartomobile-config-pkg' => {
                                                                                    'iana' => 'permanent',
                                                                                    'iana_intended_usage' => 'limited use'
                                                                                  },
                                          'vnd.coffeescript' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.collabio.xodocuments.document' => {
                                                                                 'iana' => 'permanent',
                                                                                 'iana_intended_usage' => 'common'
                                                                               },
                                          'vnd.collabio.xodocuments.document-template' => {
                                                                                          'iana' => 'permanent',
                                                                                          'iana_intended_usage' => 'common'
                                                                                        },
                                          'vnd.collabio.xodocuments.presentation' => {
                                                                                     'iana' => 'permanent',
                                                                                     'iana_intended_usage' => 'common'
                                                                                   },
                                          'vnd.collabio.xodocuments.presentation-template' => {
                                                                                              'iana' => 'permanent',
                                                                                              'iana_intended_usage' => 'common'
                                                                                            },
                                          'vnd.collabio.xodocuments.spreadsheet' => {
                                                                                    'iana' => 'permanent',
                                                                                    'iana_intended_usage' => 'common'
                                                                                  },
                                          'vnd.collabio.xodocuments.spreadsheet-template' => {
                                                                                             'iana' => 'permanent',
                                                                                             'iana_intended_usage' => 'common'
                                                                                           },
                                          'vnd.collection+json' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common',
                                                                   'params' => {
                                                                                 'profile' => {}
                                                                               }
                                                                 },
                                          'vnd.collection.doc+json' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.collection.next+json' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.comicbook+zip' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.comicbook-rar' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.commerce-battelle' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.commonspace' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.comsocaller' => {},
                                          'vnd.contact.cmsg' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'limited use'
                                                              },
                                          'vnd.corel-draw' => {},
                                          'vnd.coreos.ignition+json' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.cosmocaller' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.crick.clicker' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'vnd.crick.clicker.keyboard' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'limited use'
                                                                        },
                                          'vnd.crick.clicker.palette' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'limited use'
                                                                       },
                                          'vnd.crick.clicker.template' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'limited use'
                                                                        },
                                          'vnd.crick.clicker.wordbank' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'limited use'
                                                                        },
                                          'vnd.criticaltools.wbs+xml' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'limited use'
                                                                       },
                                          'vnd.crossref-api-message+json' => {},
                                          'vnd.crossref.deposit+xml' => {},
                                          'vnd.ctc-posml' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'limited use'
                                                           },
                                          'vnd.ctct.ws+xml' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.cups-pdf' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'vnd.cups-postscript' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'limited use'
                                                                 },
                                          'vnd.cups-ppd' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.cups-raster' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.cups-raw' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'vnd.curl' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.curl.car' => {},
                                          'vnd.curl.pcurl' => {},
                                          'vnd.cyan.dean.root+xml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'limited use'
                                                                    },
                                          'vnd.cybank' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'vnd.d2l.coursepackage1p0+zip' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.dart' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.data-vision.rdz' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'limited use'
                                                                 },
                                          'vnd.datapackage+json' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.dataresource+json' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.debian.binary-package' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.dece.data' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.dece.ttml+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.dece.unspecified' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.dece.zip' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.denovo.fcselayout-link' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'limited use'
                                                                        },
                                          'vnd.desmume-movie' => {
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.desmume.movie' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.dir-bi.plate-dl-nosuffix' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.dm.delegation+xml' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.dna' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.docker.raw-stream' => {},
                                          'vnd.document+json' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.dolby.mlp' => {},
                                          'vnd.dolby.mobile.1' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.dolby.mobile.2' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.doremir.scorecloud-binary-document' => {
                                                                                      'iana' => 'permanent',
                                                                                      'iana_intended_usage' => 'common'
                                                                                    },
                                          'vnd.dpgraph' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.dreamfactory' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.drive+json' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.ds-keypoint' => {},
                                          'vnd.dtg.local' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.dtg.local.flash' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.dtg.local.html' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.dvb.ait' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.dvb.dvbj' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.dvb.esgcontainer' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.dvb.ipdcdftnotifaccess' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.dvb.ipdcesgaccess' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.dvb.ipdcesgaccess2' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.dvb.ipdcesgpdd' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.dvb.ipdcroaming' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.dvb.iptv.alfec-base' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.dvb.iptv.alfec-enhancement' => {
                                                                              'iana' => 'permanent',
                                                                              'iana_intended_usage' => 'common'
                                                                            },
                                          'vnd.dvb.notif-aggregate-root+xml' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'common'
                                                                              },
                                          'vnd.dvb.notif-container+xml' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                          'vnd.dvb.notif-generic+xml' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.dvb.notif-ia-msglist+xml' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.dvb.notif-ia-registration-request+xml' => {
                                                                                         'iana' => 'permanent',
                                                                                         'iana_intended_usage' => 'common'
                                                                                       },
                                          'vnd.dvb.notif-ia-registration-response+xml' => {
                                                                                          'iana' => 'permanent',
                                                                                          'iana_intended_usage' => 'common'
                                                                                        },
                                          'vnd.dvb.notif-init+xml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.dvb.pfr' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.dvb.service' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.dvb.streamevent+xml' => {},
                                          'vnd.dxr' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.dynageo' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.dzr' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.easykaraoke.cdgdownload' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                          'vnd.ecdis-update' => {
                                                                'iana' => 'permanent'
                                                              },
                                          'vnd.ecip.rlp' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.ecowin.chart' => {
                                                                'iana' => 'permanent'
                                                              },
                                          'vnd.ecowin.filerequest' => {
                                                                      'iana' => 'permanent'
                                                                    },
                                          'vnd.ecowin.fileupdate' => {
                                                                     'iana' => 'permanent'
                                                                   },
                                          'vnd.ecowin.series' => {
                                                                 'iana' => 'permanent'
                                                               },
                                          'vnd.ecowin.seriesrequest' => {
                                                                        'iana' => 'permanent'
                                                                      },
                                          'vnd.ecowin.seriesupdate' => {
                                                                       'iana' => 'permanent'
                                                                     },
                                          'vnd.efi.img' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.efi.iso' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.emclient.accessrequest+xml' => {
                                                                              'iana' => 'permanent',
                                                                              'iana_intended_usage' => 'common'
                                                                            },
                                          'vnd.emusic-emusic_package' => {},
                                          'vnd.enliven' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.enphase.envoy' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'vnd.eprints.data+xml' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'vnd.epson.esf' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.epson.msf' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.epson.quickanime' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.epson.salt' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.epson.ssf' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.ericsson.quickcall' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.error+json' => {},
                                          'vnd.espass-espass+zip' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.eszigno3+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.etsi.aoc+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.etsi.asic-e+zip' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.etsi.asic-s+zip' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.etsi.cug+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.etsi.iptvcommand+xml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.etsi.iptvdiscovery+xml' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.etsi.iptvprofile+xml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.etsi.iptvsad-bc+xml' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.etsi.iptvsad-cod+xml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.etsi.iptvsad-npvr+xml' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.etsi.iptvservice+xml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.etsi.iptvsync+xml' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.etsi.iptvueprofile+xml' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.etsi.mcid+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.etsi.mheg5' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.etsi.overload-control-policy-dataset+xml' => {
                                                                                            'iana' => 'permanent',
                                                                                            'iana_intended_usage' => 'common'
                                                                                          },
                                          'vnd.etsi.pstn+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'vnd.etsi.sci+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.etsi.simservs+xml' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.etsi.timestamp-token' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.etsi.tsl+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.etsi.tsl.der' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.eudora.data' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'limited use'
                                                             },
                                          'vnd.eventstore.atom+json' => {},
                                          'vnd.eventstore.events+json' => {},
                                          'vnd.eventstore.events+xml' => {},
                                          'vnd.evernote.ink' => {},
                                          'vnd.evolv.ecig.profile' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.evolv.ecig.settings' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.evolv.ecig.theme' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.ezpix-album' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'limited use'
                                                             },
                                          'vnd.ezpix-package' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'vnd.f-secure.mobile' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'limited use'
                                                                 },
                                          'vnd.fastcopy-disk-image' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.fdf' => {
                                                       'iana' => 'permanent'
                                                     },
                                          'vnd.fdsn.mseed' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.fdsn.seed' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.ffsns' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'limited use'
                                                       },
                                          'vnd.filmit.zfc' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.fints' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'vnd.firemonkeys.cloudcell' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'limited use'
                                                                       },
                                          'vnd.flographit' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.flow.v2+json' => {},
                                          'vnd.fluxtime.clip' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.font-fontforge-sfd' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'limited use'
                                                                    },
                                          'vnd.fpx' => {},
                                          'vnd.framemaker' => {
                                                              'iana' => 'permanent',
                                                              'params' => {
                                                                            'version' => {
                                                                                         'values' => {
                                                                                                     '2.0' => {},
                                                                                                     '3.0' => {},
                                                                                                     '4.0' => {},
                                                                                                     '5.0' => {},
                                                                                                     '5.5' => {},
                                                                                                     '6.0' => {},
                                                                                                     '7.0' => {},
                                                                                                     '8.0' => {},
                                                                                                     '9.0' => {}
                                                                                                   }
                                                                                       }
                                                                          }
                                                            },
                                          'vnd.frogans.fnc' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.frogans.ltf' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.fsc.weblauch' => {},
                                          'vnd.fsc.weblaunch' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.fujitsu.oasys' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.fujitsu.oasys2' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.fujitsu.oasys3' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.fujitsu.oasysgp' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.fujitsu.oasysprs' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.fujixerox.art-ex' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.fujixerox.art4' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.fujixerox.ddd' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.fujixerox.docuworks' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.fujixerox.docuworks.binder' => {
                                                                              'iana' => 'permanent',
                                                                              'iana_intended_usage' => 'common'
                                                                            },
                                          'vnd.fujixerox.docuworks.container' => {
                                                                                 'iana' => 'permanent',
                                                                                 'iana_intended_usage' => 'common'
                                                                               },
                                          'vnd.fujixerox.hbpl' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.fut-misnet' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use'
                                                            },
                                          'vnd.futoin+json' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.fuzzysheet' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.genomatix.tuxedo' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'vnd.geo+json' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'obsolete',
                                                            'obsolete' => 1
                                                          },
                                          'vnd.geocube+xml' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'obsolete',
                                                               'obsolete' => 1
                                                             },
                                          'vnd.geogebra.file' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.geogebra.tool' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.geometry-explorer' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.geonext' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.geoplan' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.geospace' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.gerber' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'vnd.git-lfs+json' => {},
                                          'vnd.github+json' => {},
                                          'vnd.github.barred-rock-preview' => {},
                                          'vnd.github.cannonball-preview+json' => {},
                                          'vnd.github.cerberus-preview' => {},
                                          'vnd.github.drax-preview+json' => {},
                                          'vnd.github.inertia-preview+json' => {},
                                          'vnd.github.loki-preview+json' => {},
                                          'vnd.github.mirage-preview+json' => {},
                                          'vnd.github.mister-fantastic-preview+json' => {},
                                          'vnd.github.moondragon+json' => {},
                                          'vnd.github.quicksilver-preview+json' => {},
                                          'vnd.github.sersi-preview+json' => {},
                                          'vnd.github.she-hulk-preview+json' => {},
                                          'vnd.github.squirrel-girl-preview' => {},
                                          'vnd.github.swamp-thing-preview' => {},
                                          'vnd.github.the-key-preview+json' => {},
                                          'vnd.github.v3' => {},
                                          'vnd.github.v3+form' => {},
                                          'vnd.github.v3+json' => {},
                                          'vnd.github.v3.base64' => {},
                                          'vnd.github.v3.diff' => {},
                                          'vnd.github.v3.diff+json' => {},
                                          'vnd.github.v3.full+json' => {},
                                          'vnd.github.v3.html' => {},
                                          'vnd.github.v3.html+json' => {},
                                          'vnd.github.v3.patch' => {},
                                          'vnd.github.v3.patch+json' => {},
                                          'vnd.github.v3.raw+json' => {},
                                          'vnd.github.v3.text+json' => {},
                                          'vnd.github.wyandotte-preview+json' => {},
                                          'vnd.globalplatform.card-content-mgt' => {
                                                                                   'iana' => 'permanent',
                                                                                   'iana_intended_usage' => 'common'
                                                                                 },
                                          'vnd.globalplatform.card-content-mgt-response' => {
                                                                                            'iana' => 'permanent',
                                                                                            'iana_intended_usage' => 'common'
                                                                                          },
                                          'vnd.gmx' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common',
                                                       'obsolete' => 1
                                                     },
                                          'vnd.google-apps.audio' => {},
                                          'vnd.google-apps.document' => {},
                                          'vnd.google-apps.drawing' => {},
                                          'vnd.google-apps.drive-sdk' => {},
                                          'vnd.google-apps.file' => {},
                                          'vnd.google-apps.folder' => {},
                                          'vnd.google-apps.form' => {},
                                          'vnd.google-apps.freebird' => {},
                                          'vnd.google-apps.fusiontable' => {},
                                          'vnd.google-apps.kix' => {},
                                          'vnd.google-apps.photo' => {},
                                          'vnd.google-apps.presentation' => {},
                                          'vnd.google-apps.punch' => {},
                                          'vnd.google-apps.ritz' => {},
                                          'vnd.google-apps.script' => {},
                                          'vnd.google-apps.sites' => {},
                                          'vnd.google-apps.spreadsheet' => {},
                                          'vnd.google-apps.unknown' => {},
                                          'vnd.google-apps.video' => {},
                                          'vnd.google-earth.kml+xml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.google-earth.kmz' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.google.drive.ext-type.mpp' => {},
                                          'vnd.google.panorama360+jpg' => {},
                                          'vnd.gov.sk.e-form+xml' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.gov.sk.e-form+zip' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.gov.sk.xmldatacontainer+xml' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'vnd.grafeq' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'vnd.gridmp' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'limited use'
                                                        },
                                          'vnd.groove-account' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.groove-help' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.groove-identity-message' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                          'vnd.groove-injector' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.groove-tool-message' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.groove-tool-template' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.groove-vcard' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.hal+json' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.hal+xml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.handheld-entertainment+xml' => {
                                                                              'iana' => 'permanent',
                                                                              'iana_intended_usage' => 'common'
                                                                            },
                                          'vnd.hbbtv.xhtml+xml' => {},
                                          'vnd.hbci' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'limited use'
                                                      },
                                          'vnd.hc+json' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.hcl-bireports' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.hdt' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.heroku+json' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common',
                                                               'params' => {
                                                                             'indent' => {},
                                                                             'version' => {}
                                                                           }
                                                             },
                                          'vnd.hhe.lesson-player' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.hp-hpgl' => {
                                                           'iana' => 'permanent'
                                                         },
                                          'vnd.hp-hpid' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.hp-hps' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'vnd.hp-jlyt' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.hp-pcl' => {
                                                          'iana' => 'permanent'
                                                        },
                                          'vnd.hp-pclxl' => {
                                                            'iana' => 'permanent'
                                                          },
                                          'vnd.httphone' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.hydrostatix.sof-data' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.hyper+json' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.hyper-item+json' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.hyperdrive+json' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.hzn-3d-crossword' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.ibm.afplinedata' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'obsolete',
                                                                   'obsolete' => 1
                                                                 },
                                          'vnd.ibm.electronic-media' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.ibm.minipay' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.ibm.modcap' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use',
                                                              'obsolete' => 1
                                                            },
                                          'vnd.ibm.rights-management' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.ibm.secure-container' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.iccprofile' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.ieee.1905' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.igloader' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'vnd.imagemeter.folder+zip' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.imagemeter.image+zip' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.immervision-ivp' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.immervision-ivu' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.ims.imsccv1p1' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.ims.imsccv1p2' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.ims.imsccv1p3' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.ims.lis.v2.result+json' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.ims.lti.v2.toolconsumerprofile+json' => {
                                                                                       'iana' => 'permanent',
                                                                                       'iana_intended_usage' => 'common'
                                                                                     },
                                          'vnd.ims.lti.v2.toolproxy+json' => {
                                                                             'iana' => 'permanent',
                                                                             'iana_intended_usage' => 'common'
                                                                           },
                                          'vnd.ims.lti.v2.toolproxy.id+json' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'common'
                                                                              },
                                          'vnd.ims.lti.v2.toolsettings+json' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'common'
                                                                              },
                                          'vnd.ims.lti.v2.toolsettings.simple+json' => {
                                                                                       'iana' => 'permanent',
                                                                                       'iana_intended_usage' => 'common'
                                                                                     },
                                          'vnd.informedcontrol.rms+xml' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'limited use'
                                                                         },
                                          'vnd.informix-visionary' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'obsolete',
                                                                      'obsolete' => 1
                                                                    },
                                          'vnd.infotech.project' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.infotech.project+xml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.innopath.wamp.notification' => {
                                                                              'iana' => 'permanent',
                                                                              'iana_intended_usage' => 'limited use'
                                                                            },
                                          'vnd.insors.igm' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.intercon.formnet' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'vnd.intergeo' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.intertrust.digibox' => {
                                                                      'iana' => 'permanent'
                                                                    },
                                          'vnd.intertrust.nncp' => {
                                                                   'iana' => 'permanent'
                                                                 },
                                          'vnd.intu.qbo' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'vnd.intu.qfx' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'vnd.iptc.g2.catalogitem+xml' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                          'vnd.iptc.g2.conceptitem+xml' => {
                                                                           'iana' => 'permanent'
                                                                         },
                                          'vnd.iptc.g2.knowledgeitem+xml' => {
                                                                             'iana' => 'permanent'
                                                                           },
                                          'vnd.iptc.g2.newsitem+xml' => {
                                                                        'iana' => 'permanent'
                                                                      },
                                          'vnd.iptc.g2.newsmessage+xml' => {
                                                                           'iana' => 'permanent'
                                                                         },
                                          'vnd.iptc.g2.packageitem+xml' => {
                                                                           'iana' => 'permanent'
                                                                         },
                                          'vnd.iptc.g2.planningitem+xml' => {
                                                                            'iana' => 'permanent'
                                                                          },
                                          'vnd.ipunplugged.rcprofile' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'limited use'
                                                                       },
                                          'vnd.irepository.package+xml' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'limited use'
                                                                         },
                                          'vnd.is-xpr' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'vnd.isac.fcs' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.jam' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.japannet-directory-service' => {
                                                                              'iana' => 'permanent'
                                                                            },
                                          'vnd.japannet-jpnstore-wakeup' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.japannet-payment-wakeup' => {
                                                                           'iana' => 'permanent'
                                                                         },
                                          'vnd.japannet-registration' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.japannet-registration-wakeup' => {
                                                                                'iana' => 'permanent'
                                                                              },
                                          'vnd.japannet-setstore-wakeup' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.japannet-verification' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.japannet-verification-wakeup' => {
                                                                                'iana' => 'permanent'
                                                                              },
                                          'vnd.jcp.javame.midlet-rms' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.jisp' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.joost.joda-archive' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.jsk.isdn-ngn' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.kahootz' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.kddi-setsynctime' => {},
                                          'vnd.kddi-verror' => {},
                                          'vnd.kddi-vpimlist' => {},
                                          'vnd.kde.karbon' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.kde.kchart' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.kde.kformula' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.kde.kivio' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.kde.kontour' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.kde.kpresenter' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.kde.kspread' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.kde.kword' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.kenameaapp' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use'
                                                            },
                                          'vnd.kenameapp' => {},
                                          'vnd.kidspiration' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.kinar' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'vnd.koan' => {
                                                        'iana' => 'permanent'
                                                      },
                                          'vnd.kodak-descriptor' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.las.las+json' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'limited use'
                                                              },
                                          'vnd.las.las+xml' => {
                                                               'iana' => 'permanent'
                                                             },
                                          'vnd.leap+json' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.liberty-request+xml' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'limited use'
                                                                     },
                                          'vnd.littlebits.master+json' => {},
                                          'vnd.littlebits.v1+json' => {},
                                          'vnd.littlebits.v2+json' => {},
                                          'vnd.llamagraphics.life-balance.desktop' => {
                                                                                      'iana' => 'permanent',
                                                                                      'iana_intended_usage' => 'common'
                                                                                    },
                                          'vnd.llamagraphics.life-balance.exchange+xml' => {
                                                                                           'iana' => 'permanent',
                                                                                           'iana_intended_usage' => 'common'
                                                                                         },
                                          'vnd.lotus-1-2-3' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common',
                                                               'params' => {
                                                                             'version' => {
                                                                                          'values' => {
                                                                                                      '1.0' => {},
                                                                                                      '2.0' => {},
                                                                                                      '3.0' => {},
                                                                                                      '4-5' => {},
                                                                                                      '5.0' => {}
                                                                                                    }
                                                                                        }
                                                                           }
                                                             },
                                          'vnd.lotus-approach' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common',
                                                                  'params' => {
                                                                                'version' => {
                                                                                             'values' => {
                                                                                                         '97' => {}
                                                                                                       }
                                                                                           }
                                                                              }
                                                                },
                                          'vnd.lotus-freelance' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.lotus-notes' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common',
                                                               'params' => {
                                                                             'version' => {
                                                                                          'values' => {
                                                                                                      '2' => {},
                                                                                                      '3' => {},
                                                                                                      '4' => {}
                                                                                                    }
                                                                                        }
                                                                           }
                                                             },
                                          'vnd.lotus-organizer' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.lotus-screencam' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.lotus-wordpro' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common',
                                                                 'params' => {
                                                                               'version' => {
                                                                                            'values' => {
                                                                                                        '96' => {},
                                                                                                        '97/millennium' => {}
                                                                                                      }
                                                                                          }
                                                                             }
                                                               },
                                          'vnd.macports.portpkg' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.mapbox-vector-tile' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.marlin.drm.actiontoken+xml' => {
                                                                              'iana' => 'permanent',
                                                                              'iana_intended_usage' => 'common'
                                                                            },
                                          'vnd.marlin.drm.conftoken+xml' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.marlin.drm.license+xml' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.marlin.drm.mdcf' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.mason+json' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.mathworks.matlab.simulink.model' => {},
                                          'vnd.maxmind.maxmind-db' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.mcd' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.medcalcdata' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'limited use'
                                                             },
                                          'vnd.mediastation.cdkey' => {
                                                                      'iana' => 'permanent'
                                                                    },
                                          'vnd.mendeley-file.1+json' => {},
                                          'vnd.mentor_graphics.hdl_author.project_file' => {},
                                          'vnd.mentor_graphics.hdl_author.structure' => {},
                                          'vnd.mentor_graphics.hdl_author.symbol' => {},
                                          'vnd.mentor_graphics.modelsim.do_script' => {},
                                          'vnd.meridian-slingshot' => {
                                                                      'iana' => 'permanent'
                                                                    },
                                          'vnd.mfer' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.mfmp' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.micro+json' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.micrografx.flo' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.micrografx.igx' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.microsoft.portable-executable' => {
                                                                                 'iana' => 'permanent',
                                                                                 'iana_intended_usage' => 'common'
                                                                               },
                                          'vnd.microsoft.windows.thumbnail-cache' => {
                                                                                     'iana' => 'permanent',
                                                                                     'iana_intended_usage' => 'limited use'
                                                                                   },
                                          'vnd.miele+json' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.mif' => {
                                                       'iana' => 'permanent'
                                                     },
                                          'vnd.mindjet.mindmanager' => {},
                                          'vnd.minisoft-hp3000-save' => {
                                                                        'iana' => 'permanent'
                                                                      },
                                          'vnd.mitsubishi.misty-guard.trustweb' => {
                                                                                   'iana' => 'permanent',
                                                                                   'iana_intended_usage' => 'common'
                                                                                 },
                                          'vnd.mobius.daf' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use'
                                                            },
                                          'vnd.mobius.dis' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use'
                                                            },
                                          'vnd.mobius.mbk' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use'
                                                            },
                                          'vnd.mobius.mqy' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use'
                                                            },
                                          'vnd.mobius.msl' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use'
                                                            },
                                          'vnd.mobius.plc' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use'
                                                            },
                                          'vnd.mobius.txf' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use'
                                                            },
                                          'vnd.mophun.application' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.mophun.certificate' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.motorola.flexsuite' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.motorola.flexsuite.adsi' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                          'vnd.motorola.flexsuite.fis' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.motorola.flexsuite.gotap' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.motorola.flexsuite.kmr' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.motorola.flexsuite.ttc' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.motorola.flexsuite.wem' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.motorola.iprm' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.mozilla.maybe.feed' => {},
                                          'vnd.mozilla.xul+xml' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.ms' => {},
                                          'vnd.ms-3mfdocument' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.ms-access' => {},
                                          'vnd.ms-artgalry' => {
                                                               'iana' => 'permanent'
                                                             },
                                          'vnd.ms-asf' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'vnd.ms-cab-compressed' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.ms-color.iccprofile' => {},
                                          'vnd.ms-excel' => {
                                                            'iana' => 'permanent',
                                                            'params' => {
                                                                          'version' => {
                                                                                       'values' => {
                                                                                                   '2' => {},
                                                                                                   '2.x' => {},
                                                                                                   '3' => {},
                                                                                                   '3.0' => {},
                                                                                                   '4.0' => {},
                                                                                                   '4s' => {},
                                                                                                   '4w' => {},
                                                                                                   '5/95' => {},
                                                                                                   '7' => {},
                                                                                                   '8' => {},
                                                                                                   '8x' => {}
                                                                                                 }
                                                                                     }
                                                                        }
                                                          },
                                          'vnd.ms-excel.12' => {},
                                          'vnd.ms-excel.addin.macroenabled' => {},
                                          'vnd.ms-excel.addin.macroenabled.12' => {
                                                                                  'iana' => 'permanent',
                                                                                  'iana_intended_usage' => 'common',
                                                                                  'params' => {
                                                                                                'version' => {
                                                                                                             'values' => {
                                                                                                                         '2007' => {}
                                                                                                                       }
                                                                                                           }
                                                                                              }
                                                                                },
                                          'vnd.ms-excel.sheet.12' => {},
                                          'vnd.ms-excel.sheet.2' => {},
                                          'vnd.ms-excel.sheet.3' => {},
                                          'vnd.ms-excel.sheet.4' => {},
                                          'vnd.ms-excel.sheet.binary.macroenabled' => {},
                                          'vnd.ms-excel.sheet.binary.macroenabled.12' => {
                                                                                         'iana' => 'permanent',
                                                                                         'iana_intended_usage' => 'common',
                                                                                         'params' => {
                                                                                                       'version' => {
                                                                                                                    'values' => {
                                                                                                                                '2007 onwards' => {}
                                                                                                                              }
                                                                                                                  }
                                                                                                     }
                                                                                       },
                                          'vnd.ms-excel.sheet.macroenabled' => {},
                                          'vnd.ms-excel.sheet.macroenabled.12' => {
                                                                                  'iana' => 'permanent',
                                                                                  'iana_intended_usage' => 'common',
                                                                                  'params' => {
                                                                                                'version' => {
                                                                                                             'values' => {
                                                                                                                         '2007' => {}
                                                                                                                       }
                                                                                                           }
                                                                                              }
                                                                                },
                                          'vnd.ms-excel.template.macroenabled' => {},
                                          'vnd.ms-excel.template.macroenabled.12' => {
                                                                                     'iana' => 'permanent',
                                                                                     'iana_intended_usage' => 'common',
                                                                                     'params' => {
                                                                                                   'version' => {
                                                                                                                'values' => {
                                                                                                                            '2007' => {}
                                                                                                                          }
                                                                                                              }
                                                                                                 }
                                                                                   },
                                          'vnd.ms-excel.workspace.3' => {},
                                          'vnd.ms-excel.workspace.4' => {},
                                          'vnd.ms-fontobject' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.ms-htmlhelp' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.ms-ims' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'vnd.ms-lrm' => {
                                                          'iana' => 'permanent'
                                                        },
                                          'vnd.ms-mediapackage' => {},
                                          'vnd.ms-office.activex+xml' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.ms-office.calx' => {},
                                          'vnd.ms-officetheme' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.ms-opentype' => {},
                                          'vnd.ms-outlook' => {},
                                          'vnd.ms-outlook-pst' => {},
                                          'vnd.ms-package.obfuscated-opentype' => {},
                                          'vnd.ms-pki.certstore' => {},
                                          'vnd.ms-pki.pko' => {},
                                          'vnd.ms-pki.seccat' => {},
                                          'vnd.ms-pki.stl' => {},
                                          'vnd.ms-pkicertstore' => {},
                                          'vnd.ms-pkiseccat' => {},
                                          'vnd.ms-pkistl' => {},
                                          'vnd.ms-playready.initiator+xml' => {
                                                                              'iana' => 'permanent',
                                                                              'iana_intended_usage' => 'common'
                                                                            },
                                          'vnd.ms-powerpoint' => {
                                                                 'iana' => 'permanent',
                                                                 'params' => {
                                                                               'version' => {
                                                                                            'values' => {
                                                                                                        '4.0' => {},
                                                                                                        '95' => {},
                                                                                                        '97-2003' => {}
                                                                                                      }
                                                                                          }
                                                                             }
                                                               },
                                          'vnd.ms-powerpoint.addin.macroenabled.12' => {
                                                                                       'iana' => 'permanent',
                                                                                       'iana_intended_usage' => 'common',
                                                                                       'params' => {
                                                                                                     'version' => {
                                                                                                                  'values' => {
                                                                                                                              '2007' => {}
                                                                                                                            }
                                                                                                                }
                                                                                                   }
                                                                                     },
                                          'vnd.ms-powerpoint.presentation.12' => {},
                                          'vnd.ms-powerpoint.presentation.macroenabled' => {},
                                          'vnd.ms-powerpoint.presentation.macroenabled.12' => {
                                                                                              'iana' => 'permanent',
                                                                                              'iana_intended_usage' => 'common',
                                                                                              'params' => {
                                                                                                            'version' => {
                                                                                                                         'values' => {
                                                                                                                                     '2007 onwards' => {}
                                                                                                                                   }
                                                                                                                       }
                                                                                                          }
                                                                                            },
                                          'vnd.ms-powerpoint.slide.macroenabled.12' => {
                                                                                       'iana' => 'permanent',
                                                                                       'iana_intended_usage' => 'common',
                                                                                       'params' => {
                                                                                                     'version' => {
                                                                                                                  'values' => {
                                                                                                                              '2007' => {}
                                                                                                                            }
                                                                                                                }
                                                                                                   }
                                                                                     },
                                          'vnd.ms-powerpoint.slideshow.macroenabled' => {},
                                          'vnd.ms-powerpoint.slideshow.macroenabled.12' => {
                                                                                           'iana' => 'permanent',
                                                                                           'iana_intended_usage' => 'common',
                                                                                           'params' => {
                                                                                                         'version' => {
                                                                                                                      'values' => {
                                                                                                                                  '2007' => {}
                                                                                                                                }
                                                                                                                    }
                                                                                                       }
                                                                                         },
                                          'vnd.ms-powerpoint.template.macroenabled' => {},
                                          'vnd.ms-powerpoint.template.macroenabled.12' => {
                                                                                          'iana' => 'permanent',
                                                                                          'iana_intended_usage' => 'common',
                                                                                          'params' => {
                                                                                                        'version' => {
                                                                                                                     'values' => {
                                                                                                                                 '2007' => {}
                                                                                                                               }
                                                                                                                   }
                                                                                                      }
                                                                                        },
                                          'vnd.ms-pps' => {},
                                          'vnd.ms-printdevicecapabilities+xml' => {
                                                                                  'iana' => 'permanent',
                                                                                  'iana_intended_usage' => 'limited use'
                                                                                },
                                          'vnd.ms-printing.printticket+xml' => {},
                                          'vnd.ms-printschematicket+xml' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'limited use'
                                                                          },
                                          'vnd.ms-project' => {
                                                              'iana' => 'permanent',
                                                              'params' => {
                                                                            'version' => {
                                                                                         'values' => {
                                                                                                     '2000-2003' => {},
                                                                                                     '2007' => {},
                                                                                                     '2010' => {},
                                                                                                     '4.0' => {},
                                                                                                     '95' => {},
                                                                                                     '98' => {}
                                                                                                   }
                                                                                       }
                                                                          }
                                                            },
                                          'vnd.ms-publisher' => {},
                                          'vnd.ms-schedule' => {},
                                          'vnd.ms-tnef' => {
                                                           'iana' => 'permanent'
                                                         },
                                          'vnd.ms-visio' => {},
                                          'vnd.ms-visio.drawing' => {},
                                          'vnd.ms-visio.drawing.macroenabled.12' => {},
                                          'vnd.ms-visio.stencil' => {},
                                          'vnd.ms-visio.stencil.macroenabled.12' => {},
                                          'vnd.ms-visio.template' => {},
                                          'vnd.ms-visio.template.macroenabled.12' => {},
                                          'vnd.ms-visio.viewer' => {},
                                          'vnd.ms-windows.devicepairing' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.ms-windows.nwprinting.oob' => {
                                                                             'iana' => 'permanent',
                                                                             'iana_intended_usage' => 'common'
                                                                           },
                                          'vnd.ms-windows.printerpairing' => {
                                                                             'iana' => 'permanent',
                                                                             'iana_intended_usage' => 'limited use'
                                                                           },
                                          'vnd.ms-windows.wsd.oob' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.ms-wmdrm.lic-chlg-req' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'limited use'
                                                                       },
                                          'vnd.ms-wmdrm.lic-resp' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'limited use'
                                                                   },
                                          'vnd.ms-wmdrm.meter-chlg-req' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'limited use'
                                                                         },
                                          'vnd.ms-wmdrm.meter-resp' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'limited use'
                                                                     },
                                          'vnd.ms-word' => {},
                                          'vnd.ms-word.document.12' => {},
                                          'vnd.ms-word.document.macroenabled' => {},
                                          'vnd.ms-word.document.macroenabled.12' => {
                                                                                    'iana' => 'permanent',
                                                                                    'iana_intended_usage' => 'common',
                                                                                    'params' => {
                                                                                                  'version' => {
                                                                                                               'values' => {
                                                                                                                           '2007 onwards' => {}
                                                                                                                         }
                                                                                                             }
                                                                                                }
                                                                                  },
                                          'vnd.ms-word.template.macroenabled.12' => {
                                                                                    'iana' => 'permanent',
                                                                                    'iana_intended_usage' => 'common',
                                                                                    'params' => {
                                                                                                  'version' => {
                                                                                                               'values' => {
                                                                                                                           '2007 onwards' => {}
                                                                                                                         }
                                                                                                             }
                                                                                                }
                                                                                  },
                                          'vnd.ms-word.template.macroenabledtemplate' => {},
                                          'vnd.ms-works' => {
                                                            'iana' => 'permanent'
                                                          },
                                          'vnd.ms-wpl' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'vnd.ms-xpsdocument' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.ms.wms-hdr.asfv1' => {},
                                          'vnd.msa-disk-image' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.msaccess' => {},
                                          'vnd.mseq' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.msign' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'vnd.msword' => {},
                                          'vnd.multiad.creator' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.multiad.creator.cif' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.music-niff' => {
                                                              'iana' => 'permanent'
                                                            },
                                          'vnd.musician' => {
                                                            'iana' => 'permanent'
                                                          },
                                          'vnd.musicpen-clt' => {},
                                          'vnd.muvee.style' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'limited use'
                                                             },
                                          'vnd.mynfc' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'vnd.ncd.control' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'limited use'
                                                             },
                                          'vnd.ncd.reference' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'vnd.nearst.inv+json' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.nervana' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.netfpx' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'vnd.neurolanguage.nlu' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.nimn' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.nintendo.nitro.rom' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.nintendo.snes.rom' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.nitf' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.noblenet-directory' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.noblenet-sealer' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.noblenet-web' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.nokia.catalogs' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'limited use'
                                                                },
                                          'vnd.nokia.configuration-message' => {},
                                          'vnd.nokia.conml+wbxml' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.nokia.conml+xml' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.nokia.iptv.config+xml' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.nokia.isds-radio-presets' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.nokia.landmark+wbxml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.nokia.landmark+xml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.nokia.landmarkcollection+xml' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'common'
                                                                              },
                                          'vnd.nokia.n-gage.ac+xml' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.nokia.n-gage.data' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.nokia.n-gage.symbian.install' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'obsolete',
                                                                                'obsolete' => 1
                                                                              },
                                          'vnd.nokia.ncd' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'limited use'
                                                           },
                                          'vnd.nokia.ncd+xml' => {
                                                                 'obsolete' => 1
                                                               },
                                          'vnd.nokia.pcd+wbxml' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.nokia.pcd+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.nokia.radio-preset' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.nokia.radio-presets' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.nokia.ringing-tone' => {},
                                          'vnd.novadigm.edm' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.novadigm.edx' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.novadigm.ext' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.ntt-local.content-share' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                          'vnd.ntt-local.file-transfer' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                          'vnd.ntt-local.ogw_remote-access' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'vnd.ntt-local.sip-ta_remote' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                          'vnd.ntt-local.sip-ta_tcp_stream' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'vnd.oasis.opendocument.base' => {},
                                          'vnd.oasis.opendocument.chart' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.oasis.opendocument.chart-template' => {
                                                                                     'iana' => 'permanent',
                                                                                     'iana_intended_usage' => 'common'
                                                                                   },
                                          'vnd.oasis.opendocument.database' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'vnd.oasis.opendocument.formula' => {
                                                                              'iana' => 'permanent',
                                                                              'iana_intended_usage' => 'common'
                                                                            },
                                          'vnd.oasis.opendocument.formula-template' => {
                                                                                       'iana' => 'permanent',
                                                                                       'iana_intended_usage' => 'common'
                                                                                     },
                                          'vnd.oasis.opendocument.graphic-template' => {},
                                          'vnd.oasis.opendocument.graphics' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common',
                                                                               'params' => {
                                                                                             'version' => {
                                                                                                          'values' => {
                                                                                                                      '1.0' => {},
                                                                                                                      '1.1' => {},
                                                                                                                      '1.2' => {}
                                                                                                                    }
                                                                                                        }
                                                                                           }
                                                                             },
                                          'vnd.oasis.opendocument.graphics-flat-xml' => {},
                                          'vnd.oasis.opendocument.graphics-template' => {
                                                                                        'iana' => 'permanent',
                                                                                        'iana_intended_usage' => 'common'
                                                                                      },
                                          'vnd.oasis.opendocument.image' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.oasis.opendocument.image-template' => {
                                                                                     'iana' => 'permanent',
                                                                                     'iana_intended_usage' => 'common'
                                                                                   },
                                          'vnd.oasis.opendocument.presentation' => {
                                                                                   'iana' => 'permanent',
                                                                                   'iana_intended_usage' => 'common',
                                                                                   'params' => {
                                                                                                 'version' => {
                                                                                                              'values' => {
                                                                                                                          '1.0' => {},
                                                                                                                          '1.1' => {},
                                                                                                                          '1.2' => {}
                                                                                                                        }
                                                                                                            }
                                                                                               }
                                                                                 },
                                          'vnd.oasis.opendocument.presentation-flat-xml' => {},
                                          'vnd.oasis.opendocument.presentation-template' => {
                                                                                            'iana' => 'permanent',
                                                                                            'iana_intended_usage' => 'common'
                                                                                          },
                                          'vnd.oasis.opendocument.spreadsheet' => {
                                                                                  'iana' => 'permanent',
                                                                                  'iana_intended_usage' => 'common',
                                                                                  'params' => {
                                                                                                'version' => {
                                                                                                             'values' => {
                                                                                                                         '1.0' => {},
                                                                                                                         '1.1' => {},
                                                                                                                         '1.2' => {}
                                                                                                                       }
                                                                                                           }
                                                                                              }
                                                                                },
                                          'vnd.oasis.opendocument.spreadsheet-flat-xml' => {},
                                          'vnd.oasis.opendocument.spreadsheet-template' => {
                                                                                           'iana' => 'permanent',
                                                                                           'iana_intended_usage' => 'common'
                                                                                         },
                                          'vnd.oasis.opendocument.tex' => {},
                                          'vnd.oasis.opendocument.text' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common',
                                                                           'params' => {
                                                                                         'version' => {
                                                                                                      'values' => {
                                                                                                                  '1.0' => {},
                                                                                                                  '1.1' => {},
                                                                                                                  '1.2' => {}
                                                                                                                }
                                                                                                    }
                                                                                       }
                                                                         },
                                          'vnd.oasis.opendocument.text-flat-xml' => {},
                                          'vnd.oasis.opendocument.text-master' => {
                                                                                  'iana' => 'permanent',
                                                                                  'iana_intended_usage' => 'common'
                                                                                },
                                          'vnd.oasis.opendocument.text-template' => {
                                                                                    'iana' => 'permanent',
                                                                                    'iana_intended_usage' => 'common'
                                                                                  },
                                          'vnd.oasis.opendocument.text-web' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'vnd.obn' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.ocf+cbor' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.oftn.l10n+json' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.oipf.contentaccessdownload+xml' => {
                                                                                  'iana' => 'permanent',
                                                                                  'iana_intended_usage' => 'common'
                                                                                },
                                          'vnd.oipf.contentaccessstreaming+xml' => {
                                                                                   'iana' => 'permanent',
                                                                                   'iana_intended_usage' => 'common'
                                                                                 },
                                          'vnd.oipf.cspg-hexbinary' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.oipf.dae.svg+xml' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.oipf.dae.xhtml+xml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.oipf.mippvcontrolmessage+xml' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'common'
                                                                              },
                                          'vnd.oipf.pae.gem' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.oipf.spdiscovery+xml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.oipf.spdlist+xml' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.oipf.ueprofile+xml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.oipf.userprofile+xml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.olpc-sugar' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.oma-scws-config' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.oma-scws-http-request' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.oma-scws-http-response' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.oma.bcast.associated-procedure-parameter+xml' => {
                                                                                                'iana' => 'permanent',
                                                                                                'iana_intended_usage' => 'limited use'
                                                                                              },
                                          'vnd.oma.bcast.drm-trigger+xml' => {
                                                                             'iana' => 'permanent',
                                                                             'iana_intended_usage' => 'obsolete',
                                                                             'obsolete' => 1
                                                                           },
                                          'vnd.oma.bcast.imd+xml' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'limited use'
                                                                   },
                                          'vnd.oma.bcast.ltkm' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'limited use'
                                                                },
                                          'vnd.oma.bcast.notification+xml' => {
                                                                              'iana' => 'permanent',
                                                                              'iana_intended_usage' => 'limited use'
                                                                            },
                                          'vnd.oma.bcast.provisioningtrigger' => {
                                                                                 'iana' => 'permanent',
                                                                                 'iana_intended_usage' => 'limited use'
                                                                               },
                                          'vnd.oma.bcast.sgboot' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'vnd.oma.bcast.sgdd+xml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'limited use'
                                                                    },
                                          'vnd.oma.bcast.sgdu' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'limited use'
                                                                },
                                          'vnd.oma.bcast.simple-symbol-container' => {
                                                                                     'iana' => 'permanent',
                                                                                     'iana_intended_usage' => 'limited use'
                                                                                   },
                                          'vnd.oma.bcast.smartcard-trigger+xml' => {
                                                                                   'iana' => 'permanent',
                                                                                   'iana_intended_usage' => 'obsolete',
                                                                                   'obsolete' => 1
                                                                                 },
                                          'vnd.oma.bcast.sprov+xml' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'limited use'
                                                                     },
                                          'vnd.oma.bcast.stkm' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'limited use'
                                                                },
                                          'vnd.oma.cab-address-book+xml' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.oma.cab-feature-handler+xml' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'vnd.oma.cab-pcc+xml' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.oma.cab-subs-invite+xml' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                          'vnd.oma.cab-user-prefs+xml' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.oma.dcd' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'limited use'
                                                         },
                                          'vnd.oma.dcdc' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'vnd.oma.dd2+xml' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.oma.drm.content' => {},
                                          'vnd.oma.drm.message' => {},
                                          'vnd.oma.drm.risd+xml' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'vnd.oma.group-usage-list+xml' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.oma.lwm2m+json' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'limited use'
                                                                },
                                          'vnd.oma.lwm2m+tlv' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'vnd.oma.pal+xml' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'limited use'
                                                             },
                                          'vnd.oma.poc.detailed-progress-report+xml' => {
                                                                                        'iana' => 'permanent',
                                                                                        'iana_intended_usage' => 'common'
                                                                                      },
                                          'vnd.oma.poc.final-report+xml' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.oma.poc.groups+xml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.oma.poc.invocation-descriptor+xml' => {
                                                                                     'iana' => 'permanent',
                                                                                     'iana_intended_usage' => 'common'
                                                                                   },
                                          'vnd.oma.poc.optimized-progress-report+xml' => {
                                                                                         'iana' => 'permanent',
                                                                                         'iana_intended_usage' => 'common'
                                                                                       },
                                          'vnd.oma.push' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'vnd.oma.scidm.messages+xml' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'limited use'
                                                                        },
                                          'vnd.oma.xcap-directory+xml' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.omads-email+xml' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.omads-file+xml' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.omads-folder+xml' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.omaloc-supl-init' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.onepager' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.onepagertamp' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.onepagertamx' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.onepagertat' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.onepagertatp' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.onepagertatx' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.openblox.game+xml' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.openblox.game-binary' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.opendap.dap4.dataset-metadata+xml' => {},
                                          'vnd.opendap.dap4.dataset-services+xml' => {},
                                          'vnd.opendap.dap4.error+xml' => {},
                                          'vnd.opendap.org.dap4.data' => {},
                                          'vnd.openeye.oeb' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.openofficeorg.extension' => {
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                          'vnd.openstreetmap.data+xml' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.openxmlformats' => {},
                                          'vnd.openxmlformats-officedocument.custom-properties+xml' => {
                                                                                                       'iana' => 'permanent',
                                                                                                       'iana_intended_usage' => 'common'
                                                                                                     },
                                          'vnd.openxmlformats-officedocument.customxmlproperties+xml' => {
                                                                                                         'iana' => 'permanent',
                                                                                                         'iana_intended_usage' => 'common'
                                                                                                       },
                                          'vnd.openxmlformats-officedocument.drawing+xml' => {
                                                                                             'iana' => 'permanent',
                                                                                             'iana_intended_usage' => 'common'
                                                                                           },
                                          'vnd.openxmlformats-officedocument.drawingml.chart+xml' => {
                                                                                                     'iana' => 'permanent',
                                                                                                     'iana_intended_usage' => 'common'
                                                                                                   },
                                          'vnd.openxmlformats-officedocument.drawingml.chartshapes+xml' => {
                                                                                                           'iana' => 'permanent',
                                                                                                           'iana_intended_usage' => 'common'
                                                                                                         },
                                          'vnd.openxmlformats-officedocument.drawingml.diagramcolors+xml' => {
                                                                                                             'iana' => 'permanent',
                                                                                                             'iana_intended_usage' => 'common'
                                                                                                           },
                                          'vnd.openxmlformats-officedocument.drawingml.diagramdata+xml' => {
                                                                                                           'iana' => 'permanent',
                                                                                                           'iana_intended_usage' => 'common'
                                                                                                         },
                                          'vnd.openxmlformats-officedocument.drawingml.diagramlayout+xml' => {
                                                                                                             'iana' => 'permanent',
                                                                                                             'iana_intended_usage' => 'common'
                                                                                                           },
                                          'vnd.openxmlformats-officedocument.drawingml.diagramstyle+xml' => {
                                                                                                            'iana' => 'permanent',
                                                                                                            'iana_intended_usage' => 'common'
                                                                                                          },
                                          'vnd.openxmlformats-officedocument.extended-properties+xml' => {
                                                                                                         'iana' => 'permanent',
                                                                                                         'iana_intended_usage' => 'common'
                                                                                                       },
                                          'vnd.openxmlformats-officedocument.pres' => {},
                                          'vnd.openxmlformats-officedocument.presentationml.commentauthors+xml' => {
                                                                                                                   'iana' => 'permanent',
                                                                                                                   'iana_intended_usage' => 'common'
                                                                                                                 },
                                          'vnd.openxmlformats-officedocument.presentationml.comments+xml' => {
                                                                                                             'iana' => 'permanent',
                                                                                                             'iana_intended_usage' => 'common'
                                                                                                           },
                                          'vnd.openxmlformats-officedocument.presentationml.document' => {},
                                          'vnd.openxmlformats-officedocument.presentationml.handoutmaster+xml' => {
                                                                                                                  'iana' => 'permanent',
                                                                                                                  'iana_intended_usage' => 'common'
                                                                                                                },
                                          'vnd.openxmlformats-officedocument.presentationml.notesmaster+xml' => {
                                                                                                                'iana' => 'permanent',
                                                                                                                'iana_intended_usage' => 'common'
                                                                                                              },
                                          'vnd.openxmlformats-officedocument.presentationml.notesslide+xml' => {
                                                                                                               'iana' => 'permanent',
                                                                                                               'iana_intended_usage' => 'common'
                                                                                                             },
                                          'vnd.openxmlformats-officedocument.presentationml.presentation' => {
                                                                                                             'iana' => 'permanent',
                                                                                                             'iana_intended_usage' => 'common',
                                                                                                             'params' => {
                                                                                                                           'version' => {
                                                                                                                                        'values' => {
                                                                                                                                                    '2007 onwards' => {}
                                                                                                                                                  }
                                                                                                                                      }
                                                                                                                         }
                                                                                                           },
                                          'vnd.openxmlformats-officedocument.presentationml.presentation.main+xml' => {
                                                                                                                      'iana' => 'permanent',
                                                                                                                      'iana_intended_usage' => 'common'
                                                                                                                    },
                                          'vnd.openxmlformats-officedocument.presentationml.presprops+xml' => {
                                                                                                              'iana' => 'permanent',
                                                                                                              'iana_intended_usage' => 'common'
                                                                                                            },
                                          'vnd.openxmlformats-officedocument.presentationml.slide' => {
                                                                                                      'iana' => 'permanent',
                                                                                                      'iana_intended_usage' => 'common'
                                                                                                    },
                                          'vnd.openxmlformats-officedocument.presentationml.slide+xml' => {
                                                                                                          'iana' => 'permanent',
                                                                                                          'iana_intended_usage' => 'common'
                                                                                                        },
                                          'vnd.openxmlformats-officedocument.presentationml.slidelayout+xml' => {
                                                                                                                'iana' => 'permanent',
                                                                                                                'iana_intended_usage' => 'common'
                                                                                                              },
                                          'vnd.openxmlformats-officedocument.presentationml.slidemaster+xml' => {
                                                                                                                'iana' => 'permanent',
                                                                                                                'iana_intended_usage' => 'common'
                                                                                                              },
                                          'vnd.openxmlformats-officedocument.presentationml.slideshow' => {
                                                                                                          'iana' => 'permanent',
                                                                                                          'iana_intended_usage' => 'common',
                                                                                                          'params' => {
                                                                                                                        'version' => {
                                                                                                                                     'values' => {
                                                                                                                                                 '2007' => {}
                                                                                                                                               }
                                                                                                                                   }
                                                                                                                      }
                                                                                                        },
                                          'vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml' => {
                                                                                                                   'iana' => 'permanent',
                                                                                                                   'iana_intended_usage' => 'common'
                                                                                                                 },
                                          'vnd.openxmlformats-officedocument.presentationml.slideupdateinfo+xml' => {
                                                                                                                    'iana' => 'permanent',
                                                                                                                    'iana_intended_usage' => 'common'
                                                                                                                  },
                                          'vnd.openxmlformats-officedocument.presentationml.tablestyles+xml' => {
                                                                                                                'iana' => 'permanent',
                                                                                                                'iana_intended_usage' => 'common'
                                                                                                              },
                                          'vnd.openxmlformats-officedocument.presentationml.tags+xml' => {
                                                                                                         'iana' => 'permanent',
                                                                                                         'iana_intended_usage' => 'common'
                                                                                                       },
                                          'vnd.openxmlformats-officedocument.presentationml.template' => {
                                                                                                         'iana' => 'permanent',
                                                                                                         'iana_intended_usage' => 'common',
                                                                                                         'params' => {
                                                                                                                       'version' => {
                                                                                                                                    'values' => {
                                                                                                                                                '2007' => {}
                                                                                                                                              }
                                                                                                                                  }
                                                                                                                     }
                                                                                                       },
                                          'vnd.openxmlformats-officedocument.presentationml.template.main+xml' => {
                                                                                                                  'iana' => 'permanent',
                                                                                                                  'iana_intended_usage' => 'common'
                                                                                                                },
                                          'vnd.openxmlformats-officedocument.presentationml.viewprops+xml' => {
                                                                                                              'iana' => 'permanent',
                                                                                                              'iana_intended_usage' => 'common'
                                                                                                            },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.calcchain+xml' => {
                                                                                                             'iana' => 'permanent',
                                                                                                             'iana_intended_usage' => 'common'
                                                                                                           },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml' => {
                                                                                                              'iana' => 'permanent',
                                                                                                              'iana_intended_usage' => 'common'
                                                                                                            },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.comments+xml' => {
                                                                                                            'iana' => 'permanent',
                                                                                                            'iana_intended_usage' => 'common'
                                                                                                          },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.connections+xml' => {
                                                                                                               'iana' => 'permanent',
                                                                                                               'iana_intended_usage' => 'common'
                                                                                                             },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.dialogsheet+xml' => {
                                                                                                               'iana' => 'permanent',
                                                                                                               'iana_intended_usage' => 'common'
                                                                                                             },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.document' => {},
                                          'vnd.openxmlformats-officedocument.spreadsheetml.externallink+xml' => {
                                                                                                                'iana' => 'permanent',
                                                                                                                'iana_intended_usage' => 'common'
                                                                                                              },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.pivotcachedefinition+xml' => {
                                                                                                                        'iana' => 'permanent',
                                                                                                                        'iana_intended_usage' => 'common'
                                                                                                                      },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.pivotcacherecords+xml' => {
                                                                                                                     'iana' => 'permanent',
                                                                                                                     'iana_intended_usage' => 'common'
                                                                                                                   },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.pivottable+xml' => {
                                                                                                              'iana' => 'permanent',
                                                                                                              'iana_intended_usage' => 'common'
                                                                                                            },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.querytable+xml' => {
                                                                                                              'iana' => 'permanent',
                                                                                                              'iana_intended_usage' => 'common'
                                                                                                            },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.revisionheaders+xml' => {
                                                                                                                   'iana' => 'permanent',
                                                                                                                   'iana_intended_usage' => 'common'
                                                                                                                 },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.revisionlog+xml' => {
                                                                                                               'iana' => 'permanent',
                                                                                                               'iana_intended_usage' => 'common'
                                                                                                             },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.sharedstrings+xml' => {
                                                                                                                 'iana' => 'permanent',
                                                                                                                 'iana_intended_usage' => 'common'
                                                                                                               },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.sheet' => {
                                                                                                     'iana' => 'permanent',
                                                                                                     'iana_intended_usage' => 'common',
                                                                                                     'params' => {
                                                                                                                   'version' => {
                                                                                                                                'values' => {
                                                                                                                                            '2007 onwards' => {}
                                                                                                                                          }
                                                                                                                              }
                                                                                                                 }
                                                                                                   },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml' => {
                                                                                                              'iana' => 'permanent',
                                                                                                              'iana_intended_usage' => 'common'
                                                                                                            },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.sheetmetadata+xml' => {
                                                                                                                 'iana' => 'permanent',
                                                                                                                 'iana_intended_usage' => 'common'
                                                                                                               },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.styles+xml' => {
                                                                                                          'iana' => 'permanent',
                                                                                                          'iana_intended_usage' => 'common'
                                                                                                        },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.table+xml' => {
                                                                                                         'iana' => 'permanent',
                                                                                                         'iana_intended_usage' => 'common'
                                                                                                       },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.tablesinglecells+xml' => {
                                                                                                                    'iana' => 'permanent',
                                                                                                                    'iana_intended_usage' => 'common'
                                                                                                                  },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.template' => {
                                                                                                        'iana' => 'permanent',
                                                                                                        'iana_intended_usage' => 'common',
                                                                                                        'params' => {
                                                                                                                      'version' => {
                                                                                                                                   'values' => {
                                                                                                                                               '2007 onwards' => {}
                                                                                                                                             }
                                                                                                                                 }
                                                                                                                    }
                                                                                                      },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml' => {
                                                                                                                 'iana' => 'permanent',
                                                                                                                 'iana_intended_usage' => 'common'
                                                                                                               },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.usernames+xml' => {
                                                                                                             'iana' => 'permanent',
                                                                                                             'iana_intended_usage' => 'common'
                                                                                                           },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.volatiledependencies+xml' => {
                                                                                                                        'iana' => 'permanent',
                                                                                                                        'iana_intended_usage' => 'common'
                                                                                                                      },
                                          'vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml' => {
                                                                                                             'iana' => 'permanent',
                                                                                                             'iana_intended_usage' => 'common'
                                                                                                           },
                                          'vnd.openxmlformats-officedocument.theme+xml' => {
                                                                                           'iana' => 'permanent',
                                                                                           'iana_intended_usage' => 'common'
                                                                                         },
                                          'vnd.openxmlformats-officedocument.themeoverride+xml' => {
                                                                                                   'iana' => 'permanent',
                                                                                                   'iana_intended_usage' => 'common'
                                                                                                 },
                                          'vnd.openxmlformats-officedocument.vmldrawing' => {
                                                                                            'iana' => 'permanent',
                                                                                            'iana_intended_usage' => 'limited use'
                                                                                          },
                                          'vnd.openxmlformats-officedocument.word' => {},
                                          'vnd.openxmlformats-officedocument.wordprocessingml.comments+xml' => {
                                                                                                               'iana' => 'permanent',
                                                                                                               'iana_intended_usage' => 'common'
                                                                                                             },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.documen' => {},
                                          'vnd.openxmlformats-officedocument.wordprocessingml.document' => {
                                                                                                           'iana' => 'permanent',
                                                                                                           'iana_intended_usage' => 'common',
                                                                                                           'params' => {
                                                                                                                         'version' => {
                                                                                                                                      'values' => {
                                                                                                                                                  '2007 onwards' => {}
                                                                                                                                                }
                                                                                                                                    }
                                                                                                                       }
                                                                                                         },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml' => {
                                                                                                                        'iana' => 'permanent',
                                                                                                                        'iana_intended_usage' => 'common'
                                                                                                                      },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml' => {
                                                                                                                    'iana' => 'permanent',
                                                                                                                    'iana_intended_usage' => 'common'
                                                                                                                  },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml' => {
                                                                                                               'iana' => 'permanent',
                                                                                                               'iana_intended_usage' => 'common'
                                                                                                             },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.fonttable+xml' => {
                                                                                                                'iana' => 'permanent',
                                                                                                                'iana_intended_usage' => 'common'
                                                                                                              },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.footer+xml' => {
                                                                                                             'iana' => 'permanent',
                                                                                                             'iana_intended_usage' => 'common'
                                                                                                           },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml' => {
                                                                                                                'iana' => 'permanent',
                                                                                                                'iana_intended_usage' => 'common'
                                                                                                              },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml' => {
                                                                                                                'iana' => 'permanent',
                                                                                                                'iana_intended_usage' => 'common'
                                                                                                              },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.settings+xml' => {
                                                                                                               'iana' => 'permanent',
                                                                                                               'iana_intended_usage' => 'common'
                                                                                                             },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.styles+xml' => {
                                                                                                             'iana' => 'permanent',
                                                                                                             'iana_intended_usage' => 'common'
                                                                                                           },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.template' => {
                                                                                                           'iana' => 'permanent',
                                                                                                           'iana_intended_usage' => 'common',
                                                                                                           'params' => {
                                                                                                                         'version' => {
                                                                                                                                      'values' => {
                                                                                                                                                  '2007 onwards' => {}
                                                                                                                                                }
                                                                                                                                    }
                                                                                                                       }
                                                                                                         },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml' => {
                                                                                                                    'iana' => 'permanent',
                                                                                                                    'iana_intended_usage' => 'common'
                                                                                                                  },
                                          'vnd.openxmlformats-officedocument.wordprocessingml.websettings+xml' => {
                                                                                                                  'iana' => 'permanent',
                                                                                                                  'iana_intended_usage' => 'common'
                                                                                                                },
                                          'vnd.openxmlformats-package.core-properties+xml' => {
                                                                                              'iana' => 'permanent',
                                                                                              'iana_intended_usage' => 'common'
                                                                                            },
                                          'vnd.openxmlformats-package.digital-signature-xmlsignature+xml' => {
                                                                                                             'iana' => 'permanent',
                                                                                                             'iana_intended_usage' => 'common'
                                                                                                           },
                                          'vnd.openxmlformats-package.relationships+xml' => {
                                                                                            'iana' => 'permanent',
                                                                                            'iana_intended_usage' => 'common'
                                                                                          },
                                          'vnd.oracle.resource+json' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.orange.indata' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.osa.netdeploy' => {
                                                                 'iana' => 'permanent'
                                                               },
                                          'vnd.osgeo.mapguide.package' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.osgi.bundle' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.osgi.dp' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.osgi.subsystem' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.otps.ct-kip+xml' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.oxli.countgraph' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.pagerduty+json' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.palm' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.panoply' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.paos+xml' => {
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'vnd.paos.xml' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'vnd.patentdive' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.pawaafile' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.pcos' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.pdf' => {},
                                          'vnd.pg.format' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'limited use'
                                                           },
                                          'vnd.pg.osasli' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'limited use'
                                                           },
                                          'vnd.phonecom.mmc-wbxml' => {},
                                          'vnd.phonecom.mmc-xml' => {},
                                          'vnd.piaccess.application-licence' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'common'
                                                                              },
                                          'vnd.picsel' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'vnd.pmi.widget' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.poc.group-advertisement+xml' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'vnd.pocketlearn' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.powerbuilder6' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'vnd.powerbuilder6-s' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'limited use'
                                                                 },
                                          'vnd.powerbuilder7' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'vnd.powerbuilder7-s' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'limited use'
                                                                 },
                                          'vnd.powerbuilder75' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'limited use'
                                                                },
                                          'vnd.powerbuilder75-s' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'vnd.preminet' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'vnd.previewsystems.box' => {
                                                                      'iana' => 'permanent'
                                                                    },
                                          'vnd.proteus.magazine' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'vnd.psfs' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.publishare-delta-tree' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'limited use'
                                                                       },
                                          'vnd.pvi.ptid1' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.pwg-multiplexed' => {
                                                                   'iana' => 'permanent'
                                                                 },
                                          'vnd.pwg-xhtml-print+xml' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.pwg-xmhtml-print+xml' => {},
                                          'vnd.qualcomm.brew-app-res' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'limited use'
                                                                       },
                                          'vnd.quarantainenet' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.quark.quarkxpress' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.quobject-quoxdocument' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.radisys.moml+xml' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.radisys.msml+xml' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.radisys.msml-audit+xml' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.radisys.msml-audit-conf+xml' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'vnd.radisys.msml-audit-conn+xml' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'vnd.radisys.msml-audit-dialog+xml' => {
                                                                                 'iana' => 'permanent',
                                                                                 'iana_intended_usage' => 'common'
                                                                               },
                                          'vnd.radisys.msml-audit-stream+xml' => {
                                                                                 'iana' => 'permanent',
                                                                                 'iana_intended_usage' => 'common'
                                                                               },
                                          'vnd.radisys.msml-conf+xml' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.radisys.msml-dialog+xml' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                          'vnd.radisys.msml-dialog-base+xml' => {
                                                                                'iana' => 'permanent',
                                                                                'iana_intended_usage' => 'common'
                                                                              },
                                          'vnd.radisys.msml-dialog-fax-detect+xml' => {
                                                                                      'iana' => 'permanent',
                                                                                      'iana_intended_usage' => 'common'
                                                                                    },
                                          'vnd.radisys.msml-dialog-fax-sendrecv+xml' => {
                                                                                        'iana' => 'permanent',
                                                                                        'iana_intended_usage' => 'common'
                                                                                      },
                                          'vnd.radisys.msml-dialog-group+xml' => {
                                                                                 'iana' => 'permanent',
                                                                                 'iana_intended_usage' => 'common'
                                                                               },
                                          'vnd.radisys.msml-dialog-speech+xml' => {
                                                                                  'iana' => 'permanent',
                                                                                  'iana_intended_usage' => 'common'
                                                                                },
                                          'vnd.radisys.msml-dialog-transform+xml' => {
                                                                                     'iana' => 'permanent',
                                                                                     'iana_intended_usage' => 'common'
                                                                                   },
                                          'vnd.rainstor.data' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.rapid' => {
                                                         'iana' => 'permanent'
                                                       },
                                          'vnd.rar' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.realvnc.bed' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'limited use'
                                                             },
                                          'vnd.recordare.musicxml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.recordare.musicxml+xml' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.renlearn.rlprint' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.restful+json' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.rig.cryptonote' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.rim.cod' => {},
                                          'vnd.rn-realaudio' => {},
                                          'vnd.rn-realaudio-secure' => {},
                                          'vnd.rn-realmedia' => {},
                                          'vnd.rn-realmedia-secure' => {},
                                          'vnd.rn-realmedia-vbr' => {},
                                          'vnd.rn-realplayer' => {},
                                          'vnd.rn-realplayer-javascript' => {},
                                          'vnd.rn-realsystem-rjs' => {},
                                          'vnd.rn-realsystem-rjt' => {},
                                          'vnd.rn-realsystem-rmj' => {},
                                          'vnd.rn-realsystem-rmx' => {},
                                          'vnd.rn-recording' => {},
                                          'vnd.rn-rn_music_package' => {},
                                          'vnd.rn-rsml' => {},
                                          'vnd.roland-rns0' => {},
                                          'vnd.route66.link66+xml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.rs-274x' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.ruckus.download' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'limited use'
                                                                 },
                                          'vnd.s3sms' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'limited use'
                                                       },
                                          'vnd.sailingtracker.track' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'limited use'
                                                                      },
                                          'vnd.sbm.cid' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'limited use'
                                                         },
                                          'vnd.sbm.mid2' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use'
                                                          },
                                          'vnd.scribus' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.sealed.3df' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.sealed.csf' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.sealed.doc' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.sealed.eml' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.sealed.mht' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.sealed.net' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.sealed.ppt' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.sealed.tiff' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'vnd.sealed.xls' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.sealedmedia.softseal.html' => {
                                                                             'iana' => 'permanent',
                                                                             'iana_intended_usage' => 'common'
                                                                           },
                                          'vnd.sealedmedia.softseal.pdf' => {
                                                                            'iana' => 'permanent',
                                                                            'iana_intended_usage' => 'common'
                                                                          },
                                          'vnd.seemail' => {
                                                           'iana' => 'permanent'
                                                         },
                                          'vnd.sema' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.semd' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.semf' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.shana.informed.formdata' => {
                                                                           'iana' => 'permanent'
                                                                         },
                                          'vnd.shana.informed.formtemplate' => {
                                                                               'iana' => 'permanent'
                                                                             },
                                          'vnd.shana.informed.interchange' => {
                                                                              'iana' => 'permanent'
                                                                            },
                                          'vnd.shana.informed.package' => {
                                                                          'iana' => 'permanent'
                                                                        },
                                          'vnd.shootproof+json' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.sigrok.session' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.simtech-mindmapper' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.siren+json' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.sketchup.skp' => {},
                                          'vnd.smaf' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.smart.notebook' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.smart.teacher' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.snap-ci.com.v1+json' => {},
                                          'vnd.soa.v71+json' => {},
                                          'vnd.soa.v71+xml' => {},
                                          'vnd.soa.v72+json' => {},
                                          'vnd.soa.v72+xml' => {},
                                          'vnd.software602.filler.form+xml' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'vnd.software602.filler.form-xml-zip' => {
                                                                                   'iana' => 'permanent',
                                                                                   'iana_intended_usage' => 'common'
                                                                                 },
                                          'vnd.solent.sdkm+xml' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.spotfire.dxp' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.spotfire.sfs' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.sqlite3' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.sss-cod' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.sss-dtf' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.sss-ntf' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.stardivision.calc' => {
                                                                     'params' => {
                                                                                   'version' => {
                                                                                                'values' => {
                                                                                                            '5.2' => {}
                                                                                                          }
                                                                                              }
                                                                                 }
                                                                   },
                                          'vnd.stardivision.chart' => {},
                                          'vnd.stardivision.draw' => {
                                                                     'params' => {
                                                                                   'version' => {
                                                                                                'values' => {
                                                                                                            '5.1' => {},
                                                                                                            '5.2' => {}
                                                                                                          }
                                                                                              }
                                                                                 }
                                                                   },
                                          'vnd.stardivision.impress' => {
                                                                        'params' => {
                                                                                      'version' => {
                                                                                                   'values' => {
                                                                                                               '5.2' => {}
                                                                                                             }
                                                                                                 }
                                                                                    }
                                                                      },
                                          'vnd.stardivision.impress-packed' => {},
                                          'vnd.stardivision.mail' => {},
                                          'vnd.stardivision.math' => {},
                                          'vnd.stardivision.writer' => {
                                                                       'params' => {
                                                                                     'version' => {
                                                                                                  'values' => {
                                                                                                              '5.1' => {},
                                                                                                              '5.2' => {}
                                                                                                            }
                                                                                                }
                                                                                   }
                                                                     },
                                          'vnd.stardivision.writer-global' => {},
                                          'vnd.staroffice.writer' => {},
                                          'vnd.stepmania.package' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'limited use'
                                                                   },
                                          'vnd.stepmania.stepchart' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.street-stream' => {
                                                                 'iana' => 'permanent'
                                                               },
                                          'vnd.sun.star.hier-folder' => {},
                                          'vnd.sun.star.hier-link' => {},
                                          'vnd.sun.star.odma' => {},
                                          'vnd.sun.star.pkg-folder' => {},
                                          'vnd.sun.star.pkg-stream' => {},
                                          'vnd.sun.star.tdoc-document' => {},
                                          'vnd.sun.star.tdoc-folder' => {},
                                          'vnd.sun.star.tdoc-root' => {},
                                          'vnd.sun.star.tdoc-stream' => {},
                                          'vnd.sun.star.webdav-collection' => {},
                                          'vnd.sun.staroffice.fsys-file' => {},
                                          'vnd.sun.staroffice.fsys-folder' => {},
                                          'vnd.sun.staroffice.ftp-file' => {},
                                          'vnd.sun.staroffice.ftp-folder' => {},
                                          'vnd.sun.wadl+xml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.sun.xml.calc' => {
                                                                'params' => {
                                                                              'version' => {
                                                                                           'values' => {
                                                                                                       '1.0' => {}
                                                                                                     }
                                                                                         }
                                                                            }
                                                              },
                                          'vnd.sun.xml.calc.template' => {},
                                          'vnd.sun.xml.draw' => {
                                                                'params' => {
                                                                              'version' => {
                                                                                           'values' => {
                                                                                                       '1.0' => {}
                                                                                                     }
                                                                                         }
                                                                            }
                                                              },
                                          'vnd.sun.xml.draw.template' => {},
                                          'vnd.sun.xml.impress' => {
                                                                   'params' => {
                                                                                 'version' => {
                                                                                              'values' => {
                                                                                                          '1.0' => {}
                                                                                                        }
                                                                                            }
                                                                               }
                                                                 },
                                          'vnd.sun.xml.impress.template' => {},
                                          'vnd.sun.xml.math' => {},
                                          'vnd.sun.xml.writer' => {
                                                                  'params' => {
                                                                                'version' => {
                                                                                             'values' => {
                                                                                                         '1.0' => {}
                                                                                                       }
                                                                                           }
                                                                              }
                                                                },
                                          'vnd.sun.xml.writer.global' => {},
                                          'vnd.sun.xml.writer.template' => {},
                                          'vnd.sus-calendar' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.svd' => {
                                                       'iana' => 'permanent'
                                                     },
                                          'vnd.swiftview-ics' => {
                                                                 'iana' => 'permanent'
                                                               },
                                          'vnd.swiftview-jpeg' => {},
                                          'vnd.swiftview-zip' => {},
                                          'vnd.symbian.install' => {},
                                          'vnd.syncml+wbxml' => {},
                                          'vnd.syncml+xml' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.syncml.dm+wbxml' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.syncml.dm+xml' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.syncml.dm.notification' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.syncml.dmddf+wbxml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.syncml.dmddf+xml' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.syncml.dmtnds+wbxml' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.syncml.dmtnds+xml' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.syncml.ds.notification' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.tableschema+json' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.tao.intent-module-archive' => {
                                                                             'iana' => 'permanent',
                                                                             'iana_intended_usage' => 'common'
                                                                           },
                                          'vnd.tcpdump.pcap' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.theqvd' => {
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'vnd.think-cell.ppttc+json' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.tmd.mediaflex.api+xml' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'limited use'
                                                                       },
                                          'vnd.tml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.tmobile-livetv' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.travis-ci.2+json' => {},
                                          'vnd.tri.onesource' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'vnd.trid.tpt' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.triscape.mxs' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.trueapp' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.truedoc' => {
                                                           'iana' => 'permanent'
                                                         },
                                          'vnd.tve-trigger' => {},
                                          'vnd.ubisoft.webplayer' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.ufdl' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.uiq.theme' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'limited use'
                                                           },
                                          'vnd.umajin' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'vnd.unity' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'vnd.uoml+xml' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.uplanet.alert' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.uplanet.alert-wbxml' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.uplanet.bearer-choice' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.uplanet.bearer-choice-wbxml' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'vnd.uplanet.cacheop' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.uplanet.cacheop-wbxml' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.uplanet.channel' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.uplanet.channel-wbxml' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.uplanet.list' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.uplanet.list-wbxml' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.uplanet.listcmd' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.uplanet.listcmd-wbxml' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.uplanet.signal' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.uri-map' => {
                                                           'iana' => 'permanent'
                                                         },
                                          'vnd.valve.source.material' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.vcx' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.vd-study' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.vectorworks' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'limited use'
                                                             },
                                          'vnd.vel+json' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.verimatrix.vcas' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.vidsoft.vidconference' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.visio' => {
                                                         'iana' => 'permanent',
                                                         'params' => {
                                                                       'version' => {
                                                                                    'values' => {
                                                                                                '2000' => {},
                                                                                                '2002' => {},
                                                                                                '2003' => {},
                                                                                                '5.0' => {}
                                                                                              }
                                                                                  }
                                                                     }
                                                       },
                                          'vnd.visionary' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.vividence.scriptfile' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'vnd.viwi.v1.4.2+json' => {},
                                          'vnd.vmware.admin.catalog+xml' => {},
                                          'vnd.vmware.admin.diskcreateparams+xml' => {},
                                          'vnd.vmware.admin.edgegateway+xml' => {},
                                          'vnd.vmware.admin.edgegatewayserviceconfiguration+xml' => {},
                                          'vnd.vmware.admin.organization+xml' => {},
                                          'vnd.vmware.admin.orgsettings+xml' => {},
                                          'vnd.vmware.admin.preparehostparams+xml' => {},
                                          'vnd.vmware.admin.resourcepoolsetupdateparams+xml' => {},
                                          'vnd.vmware.admin.right+xml' => {},
                                          'vnd.vmware.admin.service+xml' => {},
                                          'vnd.vmware.admin.systemsettings+xml' => {},
                                          'vnd.vmware.admin.user+xml' => {},
                                          'vnd.vmware.admin.vcloud+xml' => {},
                                          'vnd.vmware.admin.vmsobjectrefslist+xml' => {},
                                          'vnd.vmware.admin.vmwextension+xml' => {},
                                          'vnd.vmware.admin.vmwexternalnet+xml' => {},
                                          'vnd.vmware.admin.vmwprovidervdc+xml' => {},
                                          'vnd.vmware.admin.vmwpvdcstorageprofile+xml' => {},
                                          'vnd.vmware.admin.vmwvirtualcenter+xml' => {},
                                          'vnd.vmware.vcloud.catalogitem+xml' => {},
                                          'vnd.vmware.vcloud.clonemediaparams+xml' => {},
                                          'vnd.vmware.vcloud.clonevappparams+xml' => {},
                                          'vnd.vmware.vcloud.disk+xml' => {},
                                          'vnd.vmware.vcloud.diskcreateparams+xml' => {},
                                          'vnd.vmware.vcloud.entity+xml' => {},
                                          'vnd.vmware.vcloud.guestcustomizationsection+xml' => {},
                                          'vnd.vmware.vcloud.instantiatevapptemplateparams+xml' => {},
                                          'vnd.vmware.vcloud.media+xml' => {},
                                          'vnd.vmware.vcloud.metadata+xml' => {},
                                          'vnd.vmware.vcloud.metadata.value+xml' => {},
                                          'vnd.vmware.vcloud.networkconfigsection+xml' => {},
                                          'vnd.vmware.vcloud.networkconnectionsection+xml' => {},
                                          'vnd.vmware.vcloud.org+xml' => {},
                                          'vnd.vmware.vcloud.owner+xml' => {},
                                          'vnd.vmware.vcloud.query.querylist+xml' => {},
                                          'vnd.vmware.vcloud.recomposevappparams+xml' => {},
                                          'vnd.vmware.vcloud.session+xml' => {},
                                          'vnd.vmware.vcloud.startupsection+xml' => {},
                                          'vnd.vmware.vcloud.task+xml' => {},
                                          'vnd.vmware.vcloud.undeployvappparams+xml' => {},
                                          'vnd.vmware.vcloud.vapp+xml' => {},
                                          'vnd.vmware.vcloud.vapptemplate+xml' => {},
                                          'vnd.vmware.vcloud.vdc+xml' => {},
                                          'vnd.vmware.vcloud.virtualhardwaresection+xml' => {},
                                          'vnd.vmware.vcloud.vm+xml' => {},
                                          'vnd.vsf' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.wap.multipart.alternative' => {},
                                          'vnd.wap.multipart.byteranges' => {},
                                          'vnd.wap.multipart.form-data' => {},
                                          'vnd.wap.multipart.mixed' => {},
                                          'vnd.wap.sic' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.wap.slc' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.wap.wbxml' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'vnd.wap.wml.form.urlencode' => {},
                                          'vnd.wap.wmlc' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'vnd.wap.wmlscriptc' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.wap.xhtml+xml' => {},
                                          'vnd.webturbo' => {
                                                            'iana' => 'permanent'
                                                          },
                                          'vnd.wfa.p2p' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.wfa.wsc' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.windows.devicepairing' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'common'
                                                                       },
                                          'vnd.wmc' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'limited use'
                                                     },
                                          'vnd.wmf.bootstrap' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.wolfram.cdf' => {},
                                          'vnd.wolfram.mathematica' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.wolfram.mathematica.package' => {
                                                                               'iana' => 'permanent',
                                                                               'iana_intended_usage' => 'common'
                                                                             },
                                          'vnd.wolfram.player' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd.wordperfect' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common',
                                                               'params' => {
                                                                             'version' => {
                                                                                          'values' => {
                                                                                                      '5.0' => {},
                                                                                                      '5.1' => {},
                                                                                                      '5.2' => {},
                                                                                                      '6.0' => {}
                                                                                                    }
                                                                                        }
                                                                           }
                                                             },
                                          'vnd.wordperfect5.1' => {},
                                          'vnd.wqd' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'limited use'
                                                     },
                                          'vnd.wrq-hp3000-labelled' => {
                                                                       'iana' => 'permanent'
                                                                     },
                                          'vnd.wt.stf' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'limited use'
                                                        },
                                          'vnd.wv.csp+wbxml' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'vnd.wv.csp+xml' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.wv.ssp+xml' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.xacml+json' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.xara' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.xfdl' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'vnd.xfdl.webform' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'limited use'
                                                              },
                                          'vnd.xilinx.bitgen.binary_configuration_file' => {},
                                          'vnd.xilinx.bitgen.configuration_file' => {},
                                          'vnd.xilinx.bitgen.design_rule_check_file' => {},
                                          'vnd.xilinx.bitgen.internal' => {},
                                          'vnd.xilinx.bitgen.report' => {},
                                          'vnd.xilinx.chipscope.definition_file' => {},
                                          'vnd.xilinx.chipscope.project_file' => {},
                                          'vnd.xilinx.coregen.arch_wizard_file' => {},
                                          'vnd.xilinx.coregen.parameter_file' => {},
                                          'vnd.xilinx.coregen.project_file' => {},
                                          'vnd.xilinx.cpldfit.cpld_guide_file' => {},
                                          'vnd.xilinx.cpldfit.cpld_programming_file' => {},
                                          'vnd.xilinx.cpldfit.hex_bitstream_representation' => {},
                                          'vnd.xilinx.cpldfit.internal' => {},
                                          'vnd.xilinx.fpga_editor.internal' => {},
                                          'vnd.xilinx.fpga_editor.log_file' => {},
                                          'vnd.xilinx.fpga_editor.recovery_file' => {},
                                          'vnd.xilinx.impact.project_file' => {},
                                          'vnd.xilinx.internal' => {},
                                          'vnd.xilinx.ise.design_strategy_file' => {},
                                          'vnd.xilinx.ise.prj_script' => {},
                                          'vnd.xilinx.ise.project_file' => {},
                                          'vnd.xilinx.ise.report' => {},
                                          'vnd.xilinx.ise.rom_contents_description' => {},
                                          'vnd.xilinx.ise.schematic_file' => {},
                                          'vnd.xilinx.ise.symbol_file' => {},
                                          'vnd.xilinx.map.internal' => {},
                                          'vnd.xilinx.map.map_report' => {},
                                          'vnd.xilinx.map.ngd_netlist' => {},
                                          'vnd.xilinx.map.report' => {},
                                          'vnd.xilinx.ncd2edif.block_ram_population_file' => {},
                                          'vnd.xilinx.ngdbuild.cadence_signal_to_pin_mapping' => {},
                                          'vnd.xilinx.ngdbuild.internal' => {},
                                          'vnd.xilinx.ngdbuild.testbench_file' => {},
                                          'vnd.xilinx.ngdbuild.translation_report' => {},
                                          'vnd.xilinx.par.clock_region_report' => {},
                                          'vnd.xilinx.par.constraints_interaction_report' => {},
                                          'vnd.xilinx.par.ibis_report' => {},
                                          'vnd.xilinx.par.net_delay_report' => {},
                                          'vnd.xilinx.par.pad_report' => {},
                                          'vnd.xilinx.par.pad_text_report' => {},
                                          'vnd.xilinx.par.par_run_summary' => {},
                                          'vnd.xilinx.par.place_and_route_report' => {},
                                          'vnd.xilinx.par.placed_and_routed_netlist' => {},
                                          'vnd.xilinx.par.power_report' => {},
                                          'vnd.xilinx.par.unroutes_report' => {},
                                          'vnd.xilinx.partgen.architecture_and_device_information_file' => {},
                                          'vnd.xilinx.physical_contraints_file' => {},
                                          'vnd.xilinx.planahead.project_file' => {},
                                          'vnd.xilinx.promgen.internal' => {},
                                          'vnd.xilinx.promgen.prom_programming_file' => {},
                                          'vnd.xilinx.synthesis_constraints_file' => {},
                                          'vnd.xilinx.trace.internal' => {},
                                          'vnd.xilinx.trace.plain_text_timing_report' => {},
                                          'vnd.xilinx.trace.timing_report' => {},
                                          'vnd.xilinx.user_constraints_file' => {},
                                          'vnd.xilinx.user_rules_file' => {},
                                          'vnd.xilinx.vivado.design_checkpoint' => {},
                                          'vnd.xilinx.vivado.journal_file' => {},
                                          'vnd.xilinx.vivado.project_file' => {},
                                          'vnd.xilinx.vivado.xilinx_design_constraints' => {},
                                          'vnd.xilinx.xflow.command_script' => {},
                                          'vnd.xilinx.xflow.xflow_flow_file' => {},
                                          'vnd.xilinx.xflow.xflow_option_file' => {},
                                          'vnd.xilinx.xst.flags_file' => {},
                                          'vnd.xilinx.xst.library_search_order' => {},
                                          'vnd.xilinx.xst.rtl_file' => {},
                                          'vnd.xilinx.xst.synthesis_report_file' => {},
                                          'vnd.xmi+xml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'vnd.xmpie.cpkg' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.xmpie.dpkg' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.xmpie.plan' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.xmpie.ppkg' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.xmpie.xlim' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.yamaha.hv-dic' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                          'vnd.yamaha.hv-script' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                          'vnd.yamaha.hv-voice' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common'
                                                                 },
                                          'vnd.yamaha.openscoreformat' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.yamaha.openscoreformat.osfpvg+xml' => {
                                                                                     'iana' => 'permanent',
                                                                                     'iana_intended_usage' => 'common'
                                                                                   },
                                          'vnd.yamaha.remote-setup' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                          'vnd.yamaha.smaf-audio' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                          'vnd.yamaha.smaf-phrase' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.yamaha.through-ngn' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                          'vnd.yamaha.tunnel-udpencap' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common'
                                                                        },
                                          'vnd.yaoweme' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'limited use'
                                                         },
                                          'vnd.yellowriver-custom-menu' => {
                                                                           'iana' => 'permanent'
                                                                         },
                                          'vnd.youtube.yt' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'vnd.zul' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'vnd.zzazz.deck+xml' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                          'vnd_ms-excel' => {},
                                          'vnd_ms-powerpoint' => {},
                                          'vocaltec-ips' => {},
                                          'vocaltec-media-desc' => {},
                                          'vocaltec-media-file' => {},
                                          'voicexml+xml' => {
                                                            'iana' => 'permanent'
                                                          },
                                          'voucher-cms+json' => {
                                                                'iana' => 'permanent'
                                                              },
                                          'vq-rtcpxr' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'vsd' => {},
                                          'vsix' => {},
                                          'warc' => {},
                                          'wasm' => {
                                                    'iana' => 'provisional'
                                                  },
                                          'watcherinfo+xml' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'wbs.chart+xml' => {},
                                          'wcz' => {},
                                          'webpush-options+json' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                          'webspec+json' => {},
                                          'wfphelpap' => {},
                                          'wga-plugin' => {},
                                          'whoispp-query' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'whoispp-response' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                          'widget' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                          'wiki' => {},
                                          'windows-library+xml' => {},
                                          'windows-search-connector+xml' => {},
                                          'winhlp' => {},
                                          'winword' => {},
                                          'wita' => {
                                                    'iana' => 'permanent'
                                                  },
                                          'wlmoviemaker' => {},
                                          'wlwmanifest+xml' => {},
                                          'wmf' => {},
                                          'woff' => {},
                                          'won' => {
                                                   'iana' => 'provisional'
                                                 },
                                          'word' => {},
                                          'wordperf' => {},
                                          'wordperfect' => {
                                                           'obsolete' => 1
                                                         },
                                          'wordperfect5.1' => {
                                                              'iana' => 'permanent'
                                                            },
                                          'wordperfect6.0' => {},
                                          'wordperfect6.1' => {
                                                              'obsolete' => 1
                                                            },
                                          'wordperfectd' => {
                                                            'obsolete' => 1
                                                          },
                                          'wordpro' => {},
                                          'wpc' => {},
                                          'wpd' => {},
                                          'wrml' => {},
                                          'wsdl+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'wspolicy+xml' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'www-extended-log' => {},
                                          'x-' => {},
                                          'x-123' => {
                                                     'obsolete' => 1,
                                                     'params' => {
                                                                   'version' => {
                                                                                'values' => {
                                                                                            '1.0' => {},
                                                                                            '2.0' => {},
                                                                                            '5.0' => {}
                                                                                          }
                                                                              }
                                                                 }
                                                   },
                                          'x-3ds' => {},
                                          'x-7z-compressed' => {},
                                          'x-7zip-compressed' => {},
                                          'x-abiword' => {},
                                          'x-acad' => {},
                                          'x-access' => {
                                                        'obsolete' => 1
                                                      },
                                          'x-ace' => {},
                                          'x-ace-compressed' => {},
                                          'x-actionscript' => {},
                                          'x-actionscript3' => {},
                                          'x-activexcontrolaccountmanager-plugin' => {},
                                          'x-adobe-indesign' => {},
                                          'x-adobe-indesign-interchange' => {},
                                          'x-aim' => {},
                                          'x-alambik-script' => {},
                                          'x-alan-adventure-game' => {},
                                          'x-alpha-form' => {},
                                          'x-alternatiff' => {},
                                          'x-alz' => {},
                                          'x-amanda-header' => {},
                                          'x-amf' => {},
                                          'x-amipro' => {},
                                          'x-amz-json-1.0' => {},
                                          'x-amz-json-1.1' => {},
                                          'x-anm' => {},
                                          'x-annodex' => {},
                                          'x-annotator' => {},
                                          'x-apache-cache' => {},
                                          'x-apl-workspace' => {},
                                          'x-apoctrl-plugin' => {},
                                          'x-aportisdoc' => {},
                                          'x-apple-diskimage' => {},
                                          'x-appledouble' => {},
                                          'x-applescript' => {},
                                          'x-appleworks' => {},
                                          'x-applix-spreadsheet' => {},
                                          'x-applix-word' => {},
                                          'x-applixware' => {},
                                          'x-ar' => {},
                                          'x-arango-batchpart' => {},
                                          'x-arc' => {},
                                          'x-archive' => {},
                                          'x-arib-ait+xml' => {},
                                          'x-arib-ttml+xml' => {},
                                          'x-arj' => {},
                                          'x-arj-compressed' => {},
                                          'x-asap' => {},
                                          'x-asp' => {},
                                          'x-aspx' => {},
                                          'x-astrotite-afa' => {},
                                          'x-atokdic' => {},
                                          'x-atomserv+xml' => {},
                                          'x-att-a2bmusic' => {},
                                          'x-att-a2bmusic-purchase' => {},
                                          'x-auth-policy+xml' => {},
                                          'x-autherware-map' => {},
                                          'x-authorware-bin' => {},
                                          'x-authorware-map' => {},
                                          'x-authorware-seg' => {},
                                          'x-autocad' => {},
                                          'x-awingsoft-winds3d' => {},
                                          'x-awk' => {},
                                          'x-axcrypt' => {},
                                          'x-bananacad' => {},
                                          'x-base64' => {},
                                          'x-batch-smtp' => {
                                                            'text' => 1
                                                          },
                                          'x-battlelog-game-launcher-2.7.0' => {},
                                          'x-bbolin' => {},
                                          'x-bcpio' => {},
                                          'x-bdoc' => {},
                                          'x-beatnik' => {},
                                          'x-befunge' => {},
                                          'x-berkeley-db' => {
                                                             'params' => {
                                                                           'format' => {
                                                                                       'values' => {
                                                                                                   'btree' => {},
                                                                                                   'hash' => {},
                                                                                                   'log' => {},
                                                                                                   'queue' => {}
                                                                                                 }
                                                                                     },
                                                                           'version' => {
                                                                                        'values' => {
                                                                                                    '2' => {},
                                                                                                    '3' => {},
                                                                                                    '4' => {},
                                                                                                    '5' => {}
                                                                                                  }
                                                                                      }
                                                                         }
                                                           },
                                          'x-bibtex' => {},
                                          'x-bibtex-text-file' => {},
                                          'x-binary' => {},
                                          'x-binhex' => {},
                                          'x-binhex4' => {},
                                          'x-binhex40' => {},
                                          'x-bittorrent' => {},
                                          'x-blaxxuncc3d' => {},
                                          'x-blaxxuncc3dpro' => {},
                                          'x-bleeper' => {},
                                          'x-blender' => {},
                                          'x-blorb' => {},
                                          'x-bml' => {},
                                          'x-bmp' => {},
                                          'x-book' => {},
                                          'x-bootable' => {},
                                          'x-boxedit' => {},
                                          'x-bplist' => {},
                                          'x-brainfuck' => {},
                                          'x-bridge-url' => {},
                                          'x-bscontact' => {},
                                          'x-bsh' => {},
                                          'x-bytecode.elisp' => {},
                                          'x-bytecode.python' => {},
                                          'x-bz2' => {},
                                          'x-bz2-compressed' => {},
                                          'x-bzdvi' => {},
                                          'x-bzip' => {},
                                          'x-bzip-compressed-tar' => {},
                                          'x-bzip2' => {},
                                          'x-bzpdf' => {},
                                          'x-bzpostscript' => {},
                                          'x-cab' => {},
                                          'x-cab-compressed' => {},
                                          'x-cabinet' => {},
                                          'x-cabri2' => {},
                                          'x-calquick' => {},
                                          'x-cap' => {},
                                          'x-captivate' => {},
                                          'x-captureone' => {},
                                          'x-caramel' => {},
                                          'x-casio-device' => {},
                                          'x-cb7' => {},
                                          'x-cbr' => {},
                                          'x-cbt' => {},
                                          'x-cbz' => {},
                                          'x-cc3d' => {},
                                          'x-ccmx' => {},
                                          'x-cct' => {},
                                          'x-cd-image' => {},
                                          'x-cdf' => {
                                                     'text' => 1
                                                   },
                                          'x-cdlink' => {},
                                          'x-cdrdao-toc' => {},
                                          'x-cellml+xml' => {},
                                          'x-celo-digital-signature-plugin' => {},
                                          'x-cfm' => {},
                                          'x-cfs-compressed' => {},
                                          'x-cgi' => {},
                                          'x-chaiscript' => {},
                                          'x-chat' => {},
                                          'x-cheetah' => {},
                                          'x-chemdraw' => {},
                                          'x-chess-pgn' => {},
                                          'x-chm' => {},
                                          'x-chrome-extension' => {},
                                          'x-chrome-package' => {},
                                          'x-cif-tif-tiff' => {},
                                          'x-cisco-vpn-settings' => {},
                                          'x-claris-works' => {},
                                          'x-clariscad' => {},
                                          'x-class-file' => {},
                                          'x-clojure' => {},
                                          'x-clojurescript' => {},
                                          'x-cmu-raster' => {},
                                          'x-cmx' => {},
                                          'x-cnc' => {},
                                          'x-cnet-vsl' => {},
                                          'x-cocoa' => {},
                                          'x-coldfusion' => {},
                                          'x-collaboratory' => {},
                                          'x-comchat-log' => {},
                                          'x-compactpro' => {},
                                          'x-compress' => {
                                                          'obsolete' => 1
                                                        },
                                          'x-compressed' => {},
                                          'x-compressed-tar' => {},
                                          'x-conference' => {},
                                          'x-core' => {},
                                          'x-coredump' => {},
                                          'x-coreldraw' => {},
                                          'x-corelpresentations' => {},
                                          'x-corelxara' => {},
                                          'x-cpio' => {},
                                          'x-cpio-compressed' => {},
                                          'x-cprplayer' => {},
                                          'x-cpt' => {},
                                          'x-crochettime' => {},
                                          'x-crypto' => {},
                                          'x-csh' => {},
                                          'x-csi-cubexpress' => {},
                                          'x-css' => {},
                                          'x-csv' => {},
                                          'x-csv-data' => {},
                                          'x-cu-seeme' => {},
                                          'x-cu-web-conf' => {},
                                          'x-cu-web-video' => {},
                                          'x-cue' => {},
                                          'x-cult3d-object' => {},
                                          'x-curl' => {},
                                          'x-cyberxmain-plugin' => {},
                                          'x-cyberxmsg-plugin' => {},
                                          'x-cyberxoe-plugin' => {},
                                          'x-cyberxstkvw-plugin' => {},
                                          'x-cypher-query' => {},
                                          'x-cython' => {},
                                          'x-d96' => {},
                                          'x-dar' => {},
                                          'x-davmount+xml' => {},
                                          'x-db' => {},
                                          'x-dbase' => {},
                                          'x-dbf' => {},
                                          'x-dbm' => {},
                                          'x-dc-rom' => {},
                                          'x-dd+ext' => {},
                                          'x-deb' => {},
                                          'x-debian-package' => {},
                                          'x-decomail-template' => {},
                                          'x-deepv' => {},
                                          'x-deflate' => {},
                                          'x-designer' => {},
                                          'x-desktop' => {},
                                          'x-detective' => {},
                                          'x-dex' => {},
                                          'x-dfont' => {},
                                          'x-dgc-compressed' => {},
                                          'x-dia-diagram' => {},
                                          'x-dia-shape' => {},
                                          'x-digitalloca' => {},
                                          'x-director' => {
                                                          'params' => {
                                                                        'version' => {
                                                                                     'values' => {
                                                                                                 'macintosh' => {},
                                                                                                 'pc' => {}
                                                                                               }
                                                                                   }
                                                                      }
                                                        },
                                          'x-dirview' => {},
                                          'x-diskcopy' => {},
                                          'x-django-templating' => {},
                                          'x-dml' => {},
                                          'x-dms' => {},
                                          'x-docbook+xml' => {},
                                          'x-docx' => {},
                                          'x-docxconverter' => {},
                                          'x-dom-event-stream' => {},
                                          'x-doom' => {},
                                          'x-dor' => {},
                                          'x-dos-batch' => {},
                                          'x-dos_ms_excel' => {},
                                          'x-dos_ms_project' => {},
                                          'x-dosexec' => {},
                                          'x-dot' => {},
                                          'x-download' => {},
                                          'x-download-dmy' => {},
                                          'x-dpkg' => {},
                                          'x-drafting' => {},
                                          'x-drm' => {},
                                          'x-drm-v2' => {},
                                          'x-dsptype' => {},
                                          'x-dtbncx+xml' => {},
                                          'x-dtbook+xml' => {},
                                          'x-dtbresource+xml' => {},
                                          'x-dtcp1' => {},
                                          'x-dump' => {},
                                          'x-dvi' => {},
                                          'x-dwf' => {
                                                     'params' => {
                                                                   'version' => {
                                                                                'values' => {
                                                                                            '6.0' => {}
                                                                                          }
                                                                              }
                                                                 }
                                                   },
                                          'x-dwg' => {},
                                          'x-dxf' => {},
                                          'x-e-theme' => {},
                                          'x-earthtime' => {},
                                          'x-ebx' => {},
                                          'x-ecl' => {},
                                          'x-ecmascript' => {
                                                            'obsolete' => 1,
                                                            'params' => {
                                                                          'charset' => {}
                                                                        },
                                                            'scripting_language' => 'javascript',
                                                            'text' => 1
                                                          },
                                          'x-ecoin' => {},
                                          'x-egon' => {},
                                          'x-ejs' => {},
                                          'x-elc' => {},
                                          'x-elf' => {},
                                          'x-elicenseinstall' => {},
                                          'x-elisp' => {},
                                          'x-eloticket' => {},
                                          'x-emf' => {},
                                          'x-endnote-connect' => {},
                                          'x-endnote-connection' => {},
                                          'x-endnote-library' => {},
                                          'x-endnote-library-archive' => {},
                                          'x-endnote-refer' => {},
                                          'x-endnote-style' => {},
                                          'x-enterlicense' => {},
                                          'x-envoy' => {},
                                          'x-eps' => {},
                                          'x-epub+zip' => {},
                                          'x-erb' => {},
                                          'x-eskerplus' => {},
                                          'x-esrehber' => {},
                                          'x-esri-shape' => {},
                                          'x-esri-shape-index' => {},
                                          'x-etranscript' => {},
                                          'x-eva' => {},
                                          'x-evoque' => {},
                                          'x-example' => {},
                                          'x-excel' => {
                                                       'obsolete' => 1
                                                     },
                                          'x-exe' => {},
                                          'x-executable' => {},
                                          'x-executable-file' => {},
                                          'x-expandedbook' => {},
                                          'x-extension-m4a' => {},
                                          'x-extension-mp4' => {},
                                          'x-f5-host-plugin' => {},
                                          'x-fantom' => {},
                                          'x-fast' => {},
                                          'x-fastbid2-fbs' => {},
                                          'x-fax-manager' => {},
                                          'x-fax-manager-job' => {},
                                          'x-fcs' => {},
                                          'x-fictionbook+xml' => {},
                                          'x-file-download' => {},
                                          'x-filemaker' => {
                                                           'params' => {
                                                                         'version' => {
                                                                                      'values' => {
                                                                                                  '3' => {}
                                                                                                }
                                                                                    }
                                                                       }
                                                         },
                                          'x-filesystem' => {},
                                          'x-fish' => {},
                                          'x-flac' => {},
                                          'x-flash-video' => {},
                                          'x-fluid' => {},
                                          'x-focusfocus' => {},
                                          'x-font' => {},
                                          'x-font-adobe-metric' => {},
                                          'x-font-afm' => {},
                                          'x-font-bdf' => {},
                                          'x-font-dos' => {},
                                          'x-font-eot' => {},
                                          'x-font-framemaker' => {},
                                          'x-font-ghostscript' => {},
                                          'x-font-libgrx' => {},
                                          'x-font-linux-psf' => {},
                                          'x-font-opentype' => {},
                                          'x-font-otf' => {},
                                          'x-font-pcf' => {},
                                          'x-font-printer-metric' => {},
                                          'x-font-snf' => {},
                                          'x-font-speedo' => {},
                                          'x-font-sunos-news' => {},
                                          'x-font-tex' => {},
                                          'x-font-tex-tfm' => {},
                                          'x-font-truetype' => {},
                                          'x-font-ttf' => {},
                                          'x-font-ttx' => {},
                                          'x-font-type1' => {},
                                          'x-font-vfont' => {},
                                          'x-font-woff' => {},
                                          'x-fontdata' => {},
                                          'x-force-download' => {},
                                          'x-forcedownload' => {},
                                          'x-formatta' => {},
                                          'x-fortezza-ckl' => {},
                                          'x-fortezza-krl' => {},
                                          'x-forth' => {},
                                          'x-foxmail' => {},
                                          'x-fractals' => {},
                                          'x-frame' => {},
                                          'x-framefree2' => {},
                                          'x-framefree2-00' => {},
                                          'x-framemaker' => {},
                                          'x-free' => {},
                                          'x-freearc' => {},
                                          'x-freelance' => {},
                                          'x-freeloader' => {},
                                          'x-freemind' => {},
                                          'x-futuresplash' => {},
                                          'x-gameboy-rom' => {},
                                          'x-gamecube-rom' => {},
                                          'x-gba-rom' => {},
                                          'x-gca-compressed' => {},
                                          'x-gcwin' => {},
                                          'x-gdbm' => {},
                                          'x-gdl' => {},
                                          'x-gears-worker' => {},
                                          'x-gedcom' => {},
                                          'x-gedcomx-v1+json' => {},
                                          'x-gedcomx-v1+xml' => {},
                                          'x-genesis-rom' => {},
                                          'x-genshi' => {},
                                          'x-genshi-text' => {},
                                          'x-gettext' => {},
                                          'x-gettext-translation' => {},
                                          'x-ghostview' => {},
                                          'x-gimp-brush' => {},
                                          'x-gimp-gradient' => {},
                                          'x-gimp-image' => {},
                                          'x-gimp-pattern' => {},
                                          'x-glade' => {},
                                          'x-glg' => {},
                                          'x-glulx' => {},
                                          'x-gml+xml' => {},
                                          'x-gnome-app-info' => {},
                                          'x-gnome-theme-package' => {},
                                          'x-gnucash' => {},
                                          'x-gnumeric' => {},
                                          'x-gnumeric-spreadsheet' => {},
                                          'x-gnunet-directory' => {},
                                          'x-gnuplot' => {},
                                          'x-gnutar' => {},
                                          'x-go-sgf' => {},
                                          'x-gooddata-maql' => {},
                                          'x-google-chrome-pdf' => {},
                                          'x-google-chrome-print-preview-pdf' => {},
                                          'x-google-vlc-plugin' => {},
                                          'x-gopher-query' => {},
                                          'x-gps' => {},
                                          'x-gpx' => {
                                                     'params' => {
                                                                   'charset' => {
                                                                                'charset_xml' => 1
                                                                              }
                                                                 },
                                                     'text' => 1
                                                   },
                                          'x-gpx+xml' => {
                                                         'params' => {
                                                                       'charset' => {
                                                                                    'charset_xml' => 1
                                                                                  }
                                                                     },
                                                         'text' => 1
                                                       },
                                          'x-gramps-xml' => {},
                                          'x-graphing-calculator' => {},
                                          'x-graphite' => {},
                                          'x-grib' => {},
                                          'x-groupwise' => {},
                                          'x-gsm' => {},
                                          'x-gsp' => {},
                                          'x-gss' => {},
                                          'x-gstar' => {},
                                          'x-gtar' => {},
                                          'x-gtk-builder' => {},
                                          'x-gtk-text-buffer-rich-text' => {},
                                          'x-gtktalog' => {},
                                          'x-gunzip' => {},
                                          'x-gwt-dev-mode' => {},
                                          'x-gwt-hosted-mode' => {},
                                          'x-gxf' => {},
                                          'x-gz-font-linux-psf' => {},
                                          'x-gzdvi' => {},
                                          'x-gzip' => {
                                                      'obsolete' => 1
                                                    },
                                          'x-gzip-compressed' => {},
                                          'x-gzpdf' => {},
                                          'x-gzpostscript' => {},
                                          'x-hatom' => {},
                                          'x-hdf' => {},
                                          'x-hdmlc' => {},
                                          'x-helpfile' => {},
                                          'x-hep' => {},
                                          'x-hlink+xml' => {},
                                          'x-hlp' => {},
                                          'x-hta' => {},
                                          'x-htln+xml' => {},
                                          'x-html+ruby' => {},
                                          'x-htmlmail-template' => {},
                                          'x-httpd-cgi' => {},
                                          'x-httpd-eruby' => {},
                                          'x-httpd-imap' => {},
                                          'x-httpd-isapi' => {},
                                          'x-httpd-java' => {},
                                          'x-httpd-jsp' => {},
                                          'x-httpd-lasso' => {},
                                          'x-httpd-lasso8' => {},
                                          'x-httpd-lasso9' => {},
                                          'x-httpd-perl' => {},
                                          'x-httpd-php' => {},
                                          'x-httpd-php-source' => {},
                                          'x-httpd-php3' => {},
                                          'x-httpd-php3-preprocessed' => {},
                                          'x-httpd-php4' => {},
                                          'x-httpd-php4cgi' => {},
                                          'x-httpd-php5' => {},
                                          'x-httpd-php52' => {},
                                          'x-httpd-php53cgi' => {},
                                          'x-httpd-php54' => {},
                                          'x-httpd-php54cgi' => {},
                                          'x-httpd-php5cgi' => {},
                                          'x-httpd-php5s' => {},
                                          'x-httpd-php6cgi' => {},
                                          'x-httpd-phpcgi' => {},
                                          'x-httpd-phps' => {},
                                          'x-httpd-python' => {},
                                          'x-hwp' => {},
                                          'x-hwt' => {},
                                          'x-hy' => {},
                                          'x-hybrid-thrift-binary' => {},
                                          'x-hybris' => {},
                                          'x-hypercosm' => {},
                                          'x-hypercosm-3d-applet' => {},
                                          'x-i-deas' => {},
                                          'x-ibooks+zip' => {},
                                          'x-ica' => {},
                                          'x-ichitaro' => {},
                                          'x-iconbook' => {},
                                          'x-icq' => {},
                                          'x-icq-scm' => {},
                                          'x-ideas' => {},
                                          'x-idp' => {},
                                          'x-iff' => {},
                                          'x-illuminatus' => {},
                                          'x-illustrator' => {},
                                          'x-ima' => {},
                                          'x-imagemap' => {},
                                          'x-imagewebserver-ecw' => {},
                                          'x-imagewebserver-progressbar' => {},
                                          'x-imagewebserver-toolbar' => {},
                                          'x-imagewebserver2-ecw' => {},
                                          'x-indesign' => {},
                                          'x-indesign-interchange' => {},
                                          'x-inf' => {},
                                          'x-info' => {},
                                          'x-ini-file' => {},
                                          'x-inpview' => {},
                                          'x-insight' => {},
                                          'x-inspiration' => {},
                                          'x-install-instructions' => {},
                                          'x-installer' => {},
                                          'x-installfromthewebrri' => {},
                                          'x-installshield' => {},
                                          'x-installshieldwis' => {},
                                          'x-internet-archive' => {
                                                                  'params' => {
                                                                                'version' => {
                                                                                             'values' => {
                                                                                                         '1.0' => {}
                                                                                                       }
                                                                                           }
                                                                              }
                                                                },
                                          'x-internet-signup' => {},
                                          'x-internett-signup' => {},
                                          'x-inventor' => {},
                                          'x-ip2' => {},
                                          'x-iphone' => {},
                                          'x-ipix' => {},
                                          'x-ipod-firmware' => {},
                                          'x-ipscript' => {},
                                          'x-isatab' => {},
                                          'x-isatab-assay' => {},
                                          'x-isatab-investigation' => {},
                                          'x-ism' => {},
                                          'x-iso9660-image' => {},
                                          'x-it87' => {},
                                          'x-itunes-ipa' => {},
                                          'x-itunes-ipg' => {},
                                          'x-itunes-ipsw' => {},
                                          'x-itunes-ite' => {},
                                          'x-itunes-itlp' => {},
                                          'x-itunes-itms' => {},
                                          'x-itunes-itpc' => {},
                                          'x-iwnn' => {},
                                          'x-iwork-keynote-sffkey' => {},
                                          'x-iwork-numbers-sffnumbers' => {},
                                          'x-iwork-pages-sffpages' => {},
                                          'x-jackson-smile' => {},
                                          'x-jam' => {},
                                          'x-jar' => {},
                                          'x-java' => {},
                                          'x-java-applet' => {
                                                             'params' => {
                                                                           'jpi-version' => {},
                                                                           'version' => {}
                                                                         }
                                                           },
                                          'x-java-archive' => {},
                                          'x-java-archive-diff' => {},
                                          'x-java-bean' => {
                                                           'params' => {
                                                                         'jpi-version' => {},
                                                                         'version' => {}
                                                                       }
                                                         },
                                          'x-java-byte-code' => {},
                                          'x-java-class' => {},
                                          'x-java-commerce' => {},
                                          'x-java-jce-keystore' => {},
                                          'x-java-jnilib' => {},
                                          'x-java-jnlp-file' => {},
                                          'x-java-keystore' => {},
                                          'x-java-pack200' => {},
                                          'x-java-serialized-object' => {},
                                          'x-java-vm' => {},
                                          'x-java-vm-npruntime' => {},
                                          'x-javascript' => {
                                                            'obsolete' => 1,
                                                            'params' => {
                                                                          'charset' => {}
                                                                        },
                                                            'scripting_language' => 'javascript',
                                                            'text' => 1
                                                          },
                                          'x-javascript+cheetah' => {},
                                          'x-javascript+django' => {},
                                          'x-javascript+genshi' => {},
                                          'x-javascript+jinja' => {},
                                          'x-javascript+lasso' => {},
                                          'x-javascript+mako' => {},
                                          'x-javascript+myghty' => {},
                                          'x-javascript+php' => {},
                                          'x-javascript+ruby' => {},
                                          'x-javascript+smarty' => {},
                                          'x-javascript+spitfire' => {},
                                          'x-javascript-config' => {},
                                          'x-jbuilder-project' => {},
                                          'x-jinit-applet' => {},
                                          'x-jinit-bean' => {},
                                          'x-jinja' => {},
                                          'x-jmol' => {},
                                          'x-jpg' => {},
                                          'x-js' => {},
                                          'x-js-forum-post' => {},
                                          'x-js-hana' => {},
                                          'x-js-homepage-post' => {},
                                          'x-js-inforunner' => {},
                                          'x-js-jxw' => {},
                                          'x-js-news' => {},
                                          'x-js-sns' => {},
                                          'x-js-taro' => {},
                                          'x-jsgf' => {},
                                          'x-json' => {},
                                          'x-json+ld' => {},
                                          'x-json+rdf' => {},
                                          'x-jsonlines' => {},
                                          'x-jsonml+json' => {},
                                          'x-jsp' => {},
                                          'x-julia' => {},
                                          'x-juttle' => {},
                                          'x-karbon' => {},
                                          'x-kcf-license' => {},
                                          'x-kchart' => {},
                                          'x-kddi-auc' => {},
                                          'x-kddi-cpf' => {},
                                          'x-kddi-decoanime' => {},
                                          'x-kddi-drm' => {},
                                          'x-kddi-ezmusic' => {},
                                          'x-kddi-hmusic' => {},
                                          'x-kddi-htmlmail' => {},
                                          'x-kddi-karrange' => {},
                                          'x-kddi-kcf' => {},
                                          'x-kddi-mcx' => {},
                                          'x-kddi-playlist' => {},
                                          'x-kddi-video' => {},
                                          'x-kdelnk' => {},
                                          'x-kdevelop-project' => {},
                                          'x-kexi-connectiondata' => {},
                                          'x-kexiproject-shortcut' => {},
                                          'x-kexiproject-sqlite2' => {},
                                          'x-kexiproject-sqlite3' => {},
                                          'x-kformula' => {},
                                          'x-kid' => {},
                                          'x-killustrator' => {},
                                          'x-kivio' => {},
                                          'x-kjx' => {},
                                          'x-klaunch' => {},
                                          'x-kmcs-form-data' => {},
                                          'x-koan' => {},
                                          'x-kontour' => {},
                                          'x-kpovmodeler' => {},
                                          'x-kpresenter' => {},
                                          'x-krayon' => {},
                                          'x-krita' => {},
                                          'x-ksh' => {},
                                          'x-kspread' => {},
                                          'x-kspread-crypt' => {},
                                          'x-ksysv-package' => {},
                                          'x-kugar' => {},
                                          'x-kword' => {},
                                          'x-kword-crypt' => {},
                                          'x-l10n+json' => {},
                                          'x-labview' => {},
                                          'x-labview-exec' => {},
                                          'x-labview-vi' => {},
                                          'x-laplayer-reg' => {},
                                          'x-latex' => {},
                                          'x-ldjson' => {},
                                          'x-lha' => {},
                                          'x-lha-compressed' => {},
                                          'x-lharc' => {},
                                          'x-lhz' => {},
                                          'x-library-file' => {},
                                          'x-linux-ext2fs' => {},
                                          'x-liquid-secure' => {},
                                          'x-lirs+csv' => {
                                                          'params' => {
                                                                        'charset' => {}
                                                                      },
                                                          'text' => 1
                                                        },
                                          'x-lisp' => {},
                                          'x-livescreen' => {},
                                          'x-lk-rlestream' => {},
                                          'x-lmp' => {},
                                          'x-locale' => {},
                                          'x-lotus' => {},
                                          'x-lotus-123' => {
                                                           'obsolete' => 1
                                                         },
                                          'x-lotus-notes' => {},
                                          'x-lotus-wordpro' => {},
                                          'x-lotus123' => {},
                                          'x-lotusscreencam' => {},
                                          'x-lotuswordpro' => {},
                                          'x-lrzip' => {},
                                          'x-lrzip-compressed-tar' => {},
                                          'x-lua' => {},
                                          'x-lua-bytecode' => {},
                                          'x-lyx' => {},
                                          'x-lz4' => {},
                                          'x-lzh' => {},
                                          'x-lzh-archive' => {},
                                          'x-lzh-compressed' => {},
                                          'x-lzip' => {},
                                          'x-lzma' => {},
                                          'x-lzma-compressed-tar' => {},
                                          'x-lzop' => {},
                                          'x-lzx' => {},
                                          'x-m3g' => {},
                                          'x-m4' => {},
                                          'x-mac' => {},
                                          'x-mac-binary' => {},
                                          'x-mac-binhex' => {},
                                          'x-mac-binhex40' => {},
                                          'x-mac-compactpro' => {},
                                          'x-macbase64' => {},
                                          'x-macbinary' => {},
                                          'x-maff' => {},
                                          'x-magic-cap-package-1.0' => {},
                                          'x-magick-image' => {},
                                          'x-magicpoint' => {},
                                          'x-mail-message' => {
                                                              'params' => {
                                                                            'charset' => {}
                                                                          },
                                                              'text' => 1
                                                            },
                                          'x-mailfolder' => {},
                                          'x-maker' => {
                                                       'obsolete' => 1
                                                     },
                                          'x-makeself' => {},
                                          'x-mako' => {},
                                          'x-maple' => {},
                                          'x-mapserver' => {},
                                          'x-marimba' => {},
                                          'x-markaby' => {},
                                          'x-mascot' => {},
                                          'x-mason' => {},
                                          'x-mathcad' => {
                                                         'obsolete' => 1
                                                       },
                                          'x-mathematica-old' => {},
                                          'x-matlab-data' => {},
                                          'x-matlab-figure' => {},
                                          'x-matlab-workspace' => {},
                                          'x-matroska' => {},
                                          'x-mbayplug' => {},
                                          'x-mbedlet' => {},
                                          'x-mbms-associated-procedure-description+xml' => {},
                                          'x-mbms-deregister+xml' => {},
                                          'x-mbms-envelope+xml' => {},
                                          'x-mbms-msk+xml' => {},
                                          'x-mbms-msk-response+xml' => {},
                                          'x-mbms-protection-description+xml' => {},
                                          'x-mbms-reception-report+xml' => {},
                                          'x-mbms-register+xml' => {},
                                          'x-mbms-register-response+xml' => {},
                                          'x-mbms-user-service-description+xml' => {},
                                          'x-mcad' => {},
                                          'x-md5' => {},
                                          'x-mdb' => {},
                                          'x-mediadesc' => {},
                                          'x-mediaflow' => {},
                                          'x-meme' => {},
                                          'x-memoney' => {},
                                          'x-metalink+xml' => {},
                                          'x-microsoft.net.object.binary.base64' => {},
                                          'x-microsoft.net.object.bytearray.base64' => {},
                                          'x-microsoft.net.object.soap.base64' => {},
                                          'x-midi' => {},
                                          'x-mie' => {},
                                          'x-mif' => {},
                                          'x-mime' => {},
                                          'x-mimearchive' => {},
                                          'x-mimetype' => {},
                                          'x-mindavenueaxelstream' => {},
                                          'x-miva-compiled' => {},
                                          'x-mix-transfer' => {},
                                          'x-mms-framed' => {},
                                          'x-mmxp' => {},
                                          'x-mobipocket-ebook' => {},
                                          'x-mocha' => {},
                                          'x-moderation-al-plugin' => {},
                                          'x-moderation-plugin' => {},
                                          'x-moonscript' => {},
                                          'x-moz-file' => {},
                                          'x-moz-file-promise' => {},
                                          'x-moz-file-promise-dest-filename' => {},
                                          'x-moz-file-promise-dir' => {},
                                          'x-moz-file-promise-url' => {},
                                          'x-moz-nativehtml' => {},
                                          'x-moz-nativeimage' => {},
                                          'x-moz-node' => {},
                                          'x-moz-tabbrowser-tab' => {},
                                          'x-mozilla-bookmarks' => {},
                                          'x-mpeg' => {},
                                          'x-mpeg4-reference' => {},
                                          'x-mpegurl' => {},
                                          'x-mplayer2' => {},
                                          'x-ms-application' => {},
                                          'x-ms-dos-executable' => {},
                                          'x-ms-download' => {},
                                          'x-ms-emz' => {},
                                          'x-ms-excel' => {},
                                          'x-ms-installer' => {},
                                          'x-ms-jscript' => {},
                                          'x-ms-license' => {},
                                          'x-ms-manifest' => {},
                                          'x-ms-project' => {},
                                          'x-ms-reader' => {},
                                          'x-ms-shortcut' => {},
                                          'x-ms-tnef' => {},
                                          'x-ms-vsto' => {},
                                          'x-ms-wim' => {},
                                          'x-ms-wmd' => {},
                                          'x-ms-wmp' => {},
                                          'x-ms-wms' => {},
                                          'x-ms-wmv' => {},
                                          'x-ms-wmz' => {},
                                          'x-ms-xbap' => {},
                                          'x-msaccess' => {},
                                          'x-msbinder' => {},
                                          'x-mscardfile' => {},
                                          'x-msclip' => {},
                                          'x-msdos-program' => {},
                                          'x-msdownload' => {
                                                            'params' => {
                                                                          'format' => {
                                                                                      'values' => {
                                                                                                  'pe' => {},
                                                                                                  'pe-arm7' => {},
                                                                                                  'pe-armLE' => {},
                                                                                                  'pe-armle' => {},
                                                                                                  'pe-itanium' => {},
                                                                                                  'pe32' => {},
                                                                                                  'pe64' => {}
                                                                                                }
                                                                                    }
                                                                        }
                                                          },
                                          'x-msexcel' => {},
                                          'x-msi' => {},
                                          'x-msm' => {},
                                          'x-msmediaview' => {},
                                          'x-msmetafile' => {},
                                          'x-msmoney' => {},
                                          'x-msoffice' => {},
                                          'x-mspowerpoint' => {},
                                          'x-msproject' => {},
                                          'x-mspublisher' => {},
                                          'x-msschedule' => {},
                                          'x-msterminal' => {},
                                          'x-msw6' => {},
                                          'x-mswinurl' => {},
                                          'x-msword' => {
                                                        'obsolete' => 1
                                                      },
                                          'x-msword-doc' => {},
                                          'x-msword-template' => {},
                                          'x-msworks' => {},
                                          'x-msworks-db' => {},
                                          'x-msworks-wp' => {},
                                          'x-mswrite' => {},
                                          'x-msx-rom' => {},
                                          'x-mtx' => {},
                                          'x-mwf' => {},
                                          'x-myghty' => {},
                                          'x-mysql-db' => {},
                                          'x-mysql-misam-compressed-index' => {},
                                          'x-mysql-misam-data' => {},
                                          'x-mysql-misam-index' => {},
                                          'x-mysql-table-definition' => {},
                                          'x-n2p-plugin' => {},
                                          'x-n64-rom' => {},
                                          'x-nacl' => {},
                                          'x-naoscheme' => {},
                                          'x-nautilus-link' => {},
                                          'x-navi-animation' => {},
                                          'x-navidoc' => {},
                                          'x-navimap' => {},
                                          'x-navistyle' => {},
                                          'x-ndjson' => {},
                                          'x-nemo' => {},
                                          'x-nes-rom' => {},
                                          'x-net-install' => {},
                                          'x-net120nm' => {},
                                          'x-netcdf' => {},
                                          'x-netfpx' => {},
                                          'x-netmc' => {},
                                          'x-netscape-revocation' => {},
                                          'x-netscape-vbauthentic-plugin' => {},
                                          'x-netshow-channel' => {},
                                          'x-neva1' => {},
                                          'x-newlisp' => {},
                                          'x-news-message-id' => {},
                                          'x-newton-compatible-pkg' => {},
                                          'x-nif' => {},
                                          'x-nintendo-ds-rom' => {},
                                          'x-nokia-9000-communicator-add-on-software' => {},
                                          'x-np-mbox' => {},
                                          'x-ns-proxy-auto-config' => {},
                                          'x-ns-proxy-autoconfig' => {},
                                          'x-nsv-vp3-mp3' => {},
                                          'x-nvat' => {},
                                          'x-nvi' => {},
                                          'x-nvml' => {},
                                          'x-nwc' => {},
                                          'x-nyp' => {},
                                          'x-nzb' => {},
                                          'x-object' => {},
                                          'x-object-file' => {},
                                          'x-octet-stream' => {},
                                          'x-octetstream' => {},
                                          'x-oebps-package+xml' => {},
                                          'x-officeforms' => {},
                                          'x-ofx' => {
                                                     'params' => {
                                                                   'version' => {
                                                                                'values' => {
                                                                                            '1.02' => {},
                                                                                            '1.03' => {},
                                                                                            '1.6' => {},
                                                                                            '2.0.3' => {},
                                                                                            '2.1.1' => {}
                                                                                          }
                                                                              }
                                                                 }
                                                   },
                                          'x-ogg' => {},
                                          'x-ole-storage' => {},
                                          'x-oleo' => {},
                                          'x-oleobject' => {},
                                          'x-olescript' => {},
                                          'x-omc' => {},
                                          'x-omcdatamaker' => {},
                                          'x-omcregerator' => {},
                                          'x-omdoc+xml' => {},
                                          'x-omniform-mailable-filler' => {},
                                          'x-onenote' => {},
                                          'x-onlive' => {},
                                          'x-onlivehead' => {},
                                          'x-onlivereg' => {},
                                          'x-openedge' => {},
                                          'x-opera-extension' => {},
                                          'x-opera-widgets' => {},
                                          'x-opsession' => {},
                                          'x-oslc-compact+xml' => {},
                                          'x-osm+xml' => {},
                                          'x-oz-application' => {},
                                          'x-p3d' => {},
                                          'x-pagemaker' => {},
                                          'x-pak' => {},
                                          'x-palmpilot' => {},
                                          'x-papirusv3' => {},
                                          'x-par2' => {},
                                          'x-parable-thing' => {},
                                          'x-partial-download' => {},
                                          'x-pasm' => {},
                                          'x-pc-engine-rom' => {},
                                          'x-pc-floppy' => {},
                                          'x-pcl' => {},
                                          'x-pcn' => {},
                                          'x-pcn-connection' => {},
                                          'x-pcnavi' => {},
                                          'x-pcvan' => {},
                                          'x-pdf' => {},
                                          'x-pef-executable' => {},
                                          'x-pem-file' => {},
                                          'x-perfmon' => {},
                                          'x-perl' => {
                                                      'params' => {
                                                                    'charset' => {}
                                                                  },
                                                      'text' => 1
                                                    },
                                          'x-perl-script' => {},
                                          'x-perl6' => {},
                                          'x-perlscript' => {
                                                            'scripting_language' => 'yes'
                                                          },
                                          'x-pert.chart+xml' => {},
                                          'x-pgp' => {},
                                          'x-pgp-message' => {},
                                          'x-phonefree' => {},
                                          'x-photodex-presenter' => {},
                                          'x-photoshop' => {},
                                          'x-php' => {},
                                          'x-php-source' => {},
                                          'x-pics-rules' => {},
                                          'x-pilot' => {},
                                          'x-pim-plugin' => {},
                                          'x-pir' => {},
                                          'x-pixclscript' => {},
                                          'x-pkcs-12' => {},
                                          'x-pkcs-crl' => {},
                                          'x-pkcs10' => {},
                                          'x-pkcs12' => {},
                                          'x-pkcs7-certificates' => {},
                                          'x-pkcs7-certreqresp' => {},
                                          'x-pkcs7-crl' => {},
                                          'x-pkcs7-mime' => {},
                                          'x-pkcs7-signature' => {},
                                          'x-pki-message' => {},
                                          'x-pkix-pkipath' => {},
                                          'x-plain' => {},
                                          'x-planperfect' => {},
                                          'x-pmd' => {},
                                          'x-pn-mpg' => {},
                                          'x-pn-npistream' => {},
                                          'x-pn-realaudio' => {},
                                          'x-pnacl' => {},
                                          'x-pnagent' => {},
                                          'x-pocket-word' => {},
                                          'x-podcast' => {},
                                          'x-pointplus' => {},
                                          'x-portable-anymap' => {},
                                          'x-postpet' => {},
                                          'x-postx-postx-envelope-plugin' => {},
                                          'x-powerpoint' => {},
                                          'x-powershell' => {},
                                          'x-ppages' => {},
                                          'x-ppapi-widevine-cdm' => {},
                                          'x-ppm' => {},
                                          'x-presentations' => {},
                                          'x-prl' => {},
                                          'x-pro_eng' => {},
                                          'x-prof' => {},
                                          'x-profile' => {},
                                          'x-project' => {
                                                         'params' => {
                                                                       'version' => {
                                                                                    'values' => {
                                                                                                '1.0' => {},
                                                                                                '3.0' => {},
                                                                                                '4.0' => {}
                                                                                              }
                                                                                  }
                                                                     }
                                                       },
                                          'x-protobuf' => {},
                                          'x-prt' => {},
                                          'x-psgi' => {},
                                          'x-pulse-download' => {},
                                          'x-pulse-player' => {},
                                          'x-pulse-player32' => {},
                                          'x-pulse-stream' => {},
                                          'x-pulse-version-5-2-0-10532' => {},
                                          'x-pw' => {},
                                          'x-pygments-tokens' => {},
                                          'x-pypylog' => {},
                                          'x-python' => {
                                                        'scripting_language' => 'yes'
                                                      },
                                          'x-python-bytecode' => {},
                                          'x-python-code' => {},
                                          'x-python3' => {},
                                          'x-qgis' => {},
                                          'x-qml' => {},
                                          'x-qplus' => {},
                                          'x-qpro' => {},
                                          'x-qsig' => {},
                                          'x-qt-plugin' => {},
                                          'x-qt-styled-widget' => {},
                                          'x-qt.qbs+qml' => {},
                                          'x-qtiplot' => {},
                                          'x-qtview' => {},
                                          'x-quattro-dos' => {},
                                          'x-quattro-pro' => {},
                                          'x-quattro-win' => {},
                                          'x-quattropro' => {},
                                          'x-quicktime-media-link' => {},
                                          'x-quicktimeplayer' => {},
                                          'x-quicktimeupdater' => {},
                                          'x-qw' => {},
                                          'x-racket' => {},
                                          'x-rad-powermedia' => {},
                                          'x-ram' => {},
                                          'x-ramoptimizer' => {},
                                          'x-rar' => {},
                                          'x-rar-compressed' => {
                                                                'params' => {
                                                                              'version' => {
                                                                                           'values' => {
                                                                                                       '2.0' => {},
                                                                                                       '2.9' => {},
                                                                                                       '5.0' => {}
                                                                                                     }
                                                                                         }
                                                                            }
                                                              },
                                          'x-rasmol' => {},
                                          'x-raw-disk-image' => {},
                                          'x-raw-disk-image-xz-compressed' => {},
                                          'x-rcs' => {},
                                          'x-rdm' => {},
                                          'x-redhat-package-manager' => {},
                                          'x-remote_printing' => {},
                                          'x-renderfx' => {},
                                          'x-research-info-systems' => {},
                                          'x-rfc-translation+xml' => {},
                                          'x-richlink' => {},
                                          'x-riff' => {},
                                          'x-ringing-tones' => {},
                                          'x-roxio-toast' => {},
                                          'x-rpm' => {},
                                          'x-rpt' => {},
                                          'x-rsd+xml' => {},
                                          'x-rsm' => {},
                                          'x-rss+xml' => {},
                                          'x-rtf' => {
                                                     'obsolete' => 1
                                                   },
                                          'x-rtsl' => {},
                                          'x-rtsp' => {},
                                          'x-ruby' => {},
                                          'x-ruby-templating' => {},
                                          'x-rx' => {},
                                          'x-sabredav-partialupdate' => {},
                                          'x-safari-safariextz' => {},
                                          'x-safari-webarchive' => {},
                                          'x-salsa' => {},
                                          'x-sami' => {},
                                          'x-sami-dnd-flag' => {},
                                          'x-sas' => {},
                                          'x-sas-access' => {},
                                          'x-sas-audit' => {},
                                          'x-sas-backup' => {},
                                          'x-sas-catalog' => {},
                                          'x-sas-data' => {},
                                          'x-sas-data-index' => {},
                                          'x-sas-dmdb' => {},
                                          'x-sas-fdb' => {},
                                          'x-sas-itemstor' => {},
                                          'x-sas-log' => {},
                                          'x-sas-mddb' => {},
                                          'x-sas-output' => {},
                                          'x-sas-program-data' => {},
                                          'x-sas-putility' => {},
                                          'x-sas-transport' => {},
                                          'x-sas-utility' => {},
                                          'x-sas-view' => {},
                                          'x-sc' => {},
                                          'x-sch' => {},
                                          'x-scheme' => {},
                                          'x-scream' => {},
                                          'x-screencam' => {},
                                          'x-sdch-dictionary' => {},
                                          'x-sdlc' => {},
                                          'x-sdp' => {},
                                          'x-sea' => {},
                                          'x-secure-download' => {},
                                          'x-seelogo' => {},
                                          'x-set' => {},
                                          'x-setupscript' => {},
                                          'x-sgi-lpr' => {},
                                          'x-sgimb' => {},
                                          'x-sgml' => {},
                                          'x-sgml-entity' => {},
                                          'x-sgml-preamble' => {},
                                          'x-sh' => {},
                                          'x-sh-session' => {},
                                          'x-shar' => {},
                                          'x-shared-library-la' => {},
                                          'x-sharedlib' => {},
                                          'x-shell-session' => {},
                                          'x-shellscript' => {},
                                          'x-shen' => {},
                                          'x-shockwave-audio' => {},
                                          'x-shockwave-authorware' => {},
                                          'x-shockwave-flash' => {
                                                                 'params' => {
                                                                               'version' => {
                                                                                            'values' => {
                                                                                                        '1' => {},
                                                                                                        '10' => {},
                                                                                                        '2' => {},
                                                                                                        '3' => {},
                                                                                                        '4' => {},
                                                                                                        '5' => {},
                                                                                                        '6' => {},
                                                                                                        '7' => {},
                                                                                                        '8' => {},
                                                                                                        '9' => {}
                                                                                                      }
                                                                                          }
                                                                             }
                                                               },
                                          'x-shockwave-flash2-preview' => {},
                                          'x-shorten' => {},
                                          'x-showcase' => {},
                                          'x-siag' => {},
                                          'x-sibelius-score' => {},
                                          'x-sibileus-scorch' => {},
                                          'x-silverlight' => {},
                                          'x-silverlight-2' => {},
                                          'x-silverlight-2-b1' => {},
                                          'x-silverlight-2-b2' => {},
                                          'x-silverlight-app' => {},
                                          'x-simple-message-summary' => {},
                                          'x-sit' => {},
                                          'x-sitx' => {},
                                          'x-sla' => {},
                                          'x-sld' => {},
                                          'x-slim' => {},
                                          'x-slp' => {},
                                          'x-smaf' => {},
                                          'x-smarttech-notebook' => {},
                                          'x-smarty' => {},
                                          'x-smil' => {},
                                          'x-sms-rom' => {},
                                          'x-solids' => {},
                                          'x-sounder' => {},
                                          'x-source-rpm' => {},
                                          'x-spb' => {},
                                          'x-speex' => {},
                                          'x-spitfire' => {},
                                          'x-sprite' => {},
                                          'x-spss' => {},
                                          'x-spss-por' => {},
                                          'x-spss-sav' => {},
                                          'x-spt' => {},
                                          'x-spx' => {},
                                          'x-sql' => {},
                                          'x-sqlite2' => {},
                                          'x-sqlite3' => {},
                                          'x-ssdl+xml' => {},
                                          'x-ssg' => {},
                                          'x-ssp' => {},
                                          'x-ssx' => {},
                                          'x-standardml' => {},
                                          'x-staroffice-template' => {},
                                          'x-stata' => {},
                                          'x-step' => {},
                                          'x-streaming-audio' => {},
                                          'x-streamingmedia' => {},
                                          'x-stuffit' => {},
                                          'x-stuffitx' => {},
                                          'x-subrip' => {},
                                          'x-suggestions+json' => {},
                                          'x-sum' => {},
                                          'x-sv4cpio' => {},
                                          'x-sv4crc' => {},
                                          'x-t-time_plug' => {},
                                          'x-t3vm-image' => {},
                                          'x-t602' => {},
                                          'x-tads' => {},
                                          'x-tads-game' => {},
                                          'x-tar' => {},
                                          'x-tar+gzip' => {},
                                          'x-tar-compressed' => {},
                                          'x-tar-gz' => {},
                                          'x-tar-gzip' => {},
                                          'x-tardist' => {},
                                          'x-targa' => {},
                                          'x-tarz' => {},
                                          'x-taz' => {},
                                          'x-tbook' => {},
                                          'x-tbz' => {},
                                          'x-tcl' => {},
                                          'x-techinline-client' => {},
                                          'x-ternant-web-driver' => {},
                                          'x-terraform' => {},
                                          'x-test' => {},
                                          'x-tex' => {
                                                     'params' => {
                                                                   'charset' => {}
                                                                 },
                                                     'text' => 1
                                                   },
                                          'x-tex-gf' => {},
                                          'x-tex-pk' => {},
                                          'x-tex-tfm' => {},
                                          'x-texinfo' => {},
                                          'x-text' => {
                                                      'params' => {
                                                                    'charset' => {}
                                                                  },
                                                      'text' => 1
                                                    },
                                          'x-tf' => {},
                                          'x-tga' => {},
                                          'x-tgif' => {},
                                          'x-tgz' => {},
                                          'x-theme' => {},
                                          'x-theorist' => {},
                                          'x-thrift' => {},
                                          'x-tif' => {},
                                          'x-tiff' => {},
                                          'x-tika-iworks-protected' => {},
                                          'x-tika-java-enterprise-archive' => {},
                                          'x-tika-java-web-archive' => {},
                                          'x-tika-msoffice' => {},
                                          'x-tika-msoffice-embedded' => {
                                                                        'params' => {
                                                                                      'format' => {
                                                                                                  'values' => {
                                                                                                              'comp_obj' => {},
                                                                                                              'ole10_native' => {}
                                                                                                            }
                                                                                                }
                                                                                    }
                                                                      },
                                          'x-tika-msworks-spreadsheet' => {},
                                          'x-tika-old-excel' => {},
                                          'x-tika-ooxml' => {},
                                          'x-tika-ooxml-protected' => {},
                                          'x-tika-staroffice' => {},
                                          'x-tika-unix-dump' => {},
                                          'x-tika-visio-ooxml' => {},
                                          'x-timbuktu' => {},
                                          'x-tkined' => {},
                                          'x-tlk' => {},
                                          'x-toolbook' => {},
                                          'x-toutdoux' => {},
                                          'x-trash' => {},
                                          'x-trendjavascan-plugin' => {},
                                          'x-trig' => {},
                                          'x-troff' => {
                                                       'obsolete' => 1
                                                     },
                                          'x-troff-man' => {},
                                          'x-troff-man-compressed' => {},
                                          'x-troff-me' => {},
                                          'x-troff-ms' => {},
                                          'x-troff-msvideo' => {},
                                          'x-turtle' => {},
                                          'x-tv-program-info' => {},
                                          'x-twb' => {},
                                          'x-twig' => {},
                                          'x-twinvq' => {},
                                          'x-tzo' => {},
                                          'x-u-star' => {
                                                        'obsolete' => 1
                                                      },
                                          'x-uc2-compressed' => {},
                                          'x-ufraw' => {},
                                          'x-unix-archive' => {},
                                          'x-unknown' => {},
                                          'x-unknown-application-msword' => {},
                                          'x-unknown-content-type' => {},
                                          'x-unknown-content-type-curfil' => {},
                                          'x-unknown-content-type-curlfil' => {},
                                          'x-unknown-content-type-lhasaarchive' => {},
                                          'x-unknown-content-type-vsc88.mid' => {},
                                          'x-up' => {},
                                          'x-up-alert' => {},
                                          'x-up-cacheop' => {},
                                          'x-up-device' => {},
                                          'x-up-digestentry' => {},
                                          'x-up-download' => {},
                                          'x-up-downlowpng' => {},
                                          'x-urbanviewer-for-web' => {},
                                          'x-urbiscript' => {},
                                          'x-url' => {},
                                          'x-url-encoded' => {},
                                          'x-ustar' => {},
                                          'x-uue' => {},
                                          'x-uuencode' => {},
                                          'x-vbscript' => {
                                                          'scripting_language' => 'yes',
                                                          'text' => 1
                                                        },
                                          'x-vcon-command' => {},
                                          'x-vcon-data' => {},
                                          'x-vda' => {},
                                          'x-vhd' => {},
                                          'x-videolan' => {},
                                          'x-view-source' => {},
                                          'x-virtools' => {},
                                          'x-virtoolsplayer' => {},
                                          'x-virtualbox-hdd' => {},
                                          'x-virtualbox-ova' => {},
                                          'x-virtualbox-ovf' => {},
                                          'x-virtualbox-vbox' => {},
                                          'x-virtualbox-vbox-extpack' => {},
                                          'x-virtualbox-vdi' => {},
                                          'x-virtualbox-vhd' => {},
                                          'x-virtualbox-vmdk' => {},
                                          'x-visio' => {},
                                          'x-visual-basic-class' => {},
                                          'x-visual-basic-form' => {},
                                          'x-visual-basic-form-resource' => {},
                                          'x-visual-basic-project' => {},
                                          'x-visual-basic-visual-class' => {},
                                          'x-visual-basic-window' => {},
                                          'x-visualworks-parcel' => {},
                                          'x-vividence.scriptfile' => {},
                                          'x-vlc-plugin' => {},
                                          'x-vmdk' => {},
                                          'x-vmsbackup' => {},
                                          'x-vmware-vm' => {},
                                          'x-vnd.adobe.air.file-list' => {},
                                          'x-vnd.audioexplosion.mzz' => {},
                                          'x-vnd.google.oneclickctrl.9' => {},
                                          'x-vnd.google.update3webcontrol.3' => {},
                                          'x-vnd.ibm.scs' => {},
                                          'x-vnd.ls-xpix' => {},
                                          'x-vnd.mozilla' => {},
                                          'x-vnd.mozilla.guess-from-ext' => {},
                                          'x-vnd.oasis.opendocument.base' => {},
                                          'x-vnd.oasis.opendocument.chart' => {},
                                          'x-vnd.oasis.opendocument.chart-template' => {},
                                          'x-vnd.oasis.opendocument.formula' => {},
                                          'x-vnd.oasis.opendocument.formula-template' => {},
                                          'x-vnd.oasis.opendocument.graphics' => {},
                                          'x-vnd.oasis.opendocument.graphics-template' => {},
                                          'x-vnd.oasis.opendocument.image' => {},
                                          'x-vnd.oasis.opendocument.image-template' => {},
                                          'x-vnd.oasis.opendocument.presentation' => {},
                                          'x-vnd.oasis.opendocument.presentation-template' => {},
                                          'x-vnd.oasis.opendocument.spreadsheet' => {},
                                          'x-vnd.oasis.opendocument.spreadsheet-template' => {},
                                          'x-vnd.oasis.opendocument.text' => {},
                                          'x-vnd.oasis.opendocument.text-master' => {},
                                          'x-vnd.oasis.opendocument.text-template' => {},
                                          'x-vnd.oasis.opendocument.text-web' => {},
                                          'x-vnd.rn-realplayer-javascript' => {},
                                          'x-vnd.sun.xml.writer' => {},
                                          'x-vocaltec-media-desc' => {},
                                          'x-vocaltec-media-file' => {},
                                          'x-votable+xml' => {},
                                          'x-vpeg' => {},
                                          'x-vpeg005' => {},
                                          'x-vrml' => {},
                                          'x-vsd' => {},
                                          'x-w3-isindex' => {},
                                          'x-wacom-tablet' => {},
                                          'x-wacomtabletplugin' => {},
                                          'x-wais-source' => {},
                                          'x-wbs.chart+xml' => {},
                                          'x-web-app-manifest+json' => {},
                                          'x-webarchive' => {},
                                          'x-webbasic' => {},
                                          'x-websync-plugin' => {},
                                          'x-websync2-plugin' => {},
                                          'x-wgs003' => {},
                                          'x-wgs004' => {},
                                          'x-wgs005' => {},
                                          'x-wgs006' => {},
                                          'x-wgs007' => {},
                                          'x-wgs008' => {},
                                          'x-wgs009' => {},
                                          'x-wgs010' => {},
                                          'x-wii-rom' => {},
                                          'x-wiki' => {},
                                          'x-wildtangent-host' => {},
                                          'x-wildtangent-web-driver' => {},
                                          'x-win' => {},
                                          'x-winamp-playlist' => {},
                                          'x-winamp-plugin' => {},
                                          'x-windows-installer' => {},
                                          'x-windows-registry-item' => {},
                                          'x-windows-themepack' => {},
                                          'x-wine-extension-inf' => {},
                                          'x-winexe' => {},
                                          'x-wingz' => {},
                                          'x-winhelp' => {},
                                          'x-winhlp' => {},
                                          'x-wintalk' => {},
                                          'x-wlpg-detect' => {},
                                          'x-wlpg3-detect' => {},
                                          'x-wmf' => {},
                                          'x-wms-getcontentinfo' => {},
                                          'x-wms-logstats' => {},
                                          'x-wms-sendevent' => {},
                                          'x-woff' => {},
                                          'x-word' => {
                                                      'obsolete' => 1
                                                    },
                                          'x-wordperfect' => {
                                                             'obsolete' => 1
                                                           },
                                          'x-wordperfect6' => {},
                                          'x-wordperfect6.0' => {},
                                          'x-wordperfect6.1' => {},
                                          'x-wordperfectd' => {
                                                              'obsolete' => 1
                                                            },
                                          'x-wordpro' => {},
                                          'x-world' => {},
                                          'x-worldgroup' => {},
                                          'x-wpg' => {},
                                          'x-wpwin' => {},
                                          'x-wri' => {},
                                          'x-wwf' => {},
                                          'x-www-form+xml' => {
                                                              'obsolete' => 1,
                                                              'text' => 1
                                                            },
                                          'x-www-form-data' => {},
                                          'x-www-form-encoded' => {},
                                          'x-www-form-urlencoded' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common',
                                                                     'params' => {
                                                                                   'charset' => {}
                                                                                 },
                                                                     'text' => 1
                                                                   },
                                          'x-www-local-exec' => {},
                                          'x-www-pem-reply' => {},
                                          'x-www-pem-request' => {},
                                          'x-www-pgm-reply' => {},
                                          'x-www-pgm-request' => {},
                                          'x-x400-bp' => {},
                                          'x-x509-ca-cert' => {},
                                          'x-x509-crl' => {},
                                          'x-x509-email-cert' => {},
                                          'x-x509-server-cert' => {},
                                          'x-x509-user-cert' => {},
                                          'x-xaml+xml' => {},
                                          'x-xbel' => {},
                                          'x-xcf' => {},
                                          'x-xdma' => {},
                                          'x-xfdl' => {},
                                          'x-xfig' => {},
                                          'x-xforms-actions+xml' => {
                                                                    'scripting_language' => 'yes'
                                                                  },
                                          'x-xhtml+voice+xml' => {},
                                          'x-xliff' => {},
                                          'x-xliff+xml' => {},
                                          'x-xls' => {},
                                          'x-xmind' => {},
                                          'x-xml' => {},
                                          'x-xp' => {},
                                          'x-xpinstall' => {},
                                          'x-xproc+xml' => {},
                                          'x-xspf+xml' => {},
                                          'x-xstream' => {},
                                          'x-xvlplayer' => {},
                                          'x-xvlviewer' => {},
                                          'x-xz' => {},
                                          'x-xz-compressed-tar' => {},
                                          'x-xzpdf' => {},
                                          'x-yaml' => {
                                                      'text' => 1
                                                    },
                                          'x-youkuagent' => {},
                                          'x-yumekara' => {},
                                          'x-yz1' => {},
                                          'x-zaurus-zac' => {},
                                          'x-zaurus-zbf' => {},
                                          'x-zaurus-zbk' => {},
                                          'x-zerosize' => {},
                                          'x-zip' => {},
                                          'x-zip-compressed' => {},
                                          'x-zip-compressed-fb2' => {},
                                          'x-zmachine' => {},
                                          'x-zoo' => {},
                                          'x-zsh' => {},
                                          'x-ztardist' => {},
                                          'x.microsummary+xml' => {},
                                          'x.suikawiki.config' => {
                                                                  'params' => {
                                                                                'version' => {}
                                                                              }
                                                                },
                                          'x3d-vrml' => {},
                                          'x400-bp' => {
                                                       'iana' => 'permanent'
                                                     },
                                          'x400.bp' => {
                                                       'obsolete' => 1
                                                     },
                                          'xacml+xml' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common',
                                                         'params' => {
                                                                       'charset' => {},
                                                                       'version' => {}
                                                                     },
                                                         'text' => 1
                                                       },
                                          'xaml+xml' => {},
                                          'xcap-att+xml' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'xcap-caps+xml' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'xcap-diff+xml' => {
                                                             'iana' => 'permanent'
                                                           },
                                          'xcap-el+xml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'xcap-error+xml' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'xcap-ns+xml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                          'xcon-conference-info+xml' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                          'xcon-conference-info-diff+xml' => {
                                                                             'iana' => 'permanent',
                                                                             'iana_intended_usage' => 'common'
                                                                           },
                                          'xenc+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'xgmml' => {},
                                          'xhtml+voice+xml' => {},
                                          'xhtml+xml' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common',
                                                         'params' => {
                                                                       'charset' => {},
                                                                       'profile' => {},
                                                                       'version' => {
                                                                                    'values' => {
                                                                                                '1.0' => {},
                                                                                                '1.1' => {}
                                                                                              }
                                                                                  }
                                                                     },
                                                         'text' => 1
                                                       },
                                          'xhtml-voice+xml' => {
                                                               'obsolete' => 1
                                                             },
                                          'xlc' => {},
                                          'xliff+xml' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'xls' => {},
                                          'xml' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common',
                                                   'params' => {
                                                                 'charset' => {
                                                                              'charset_rfc7303' => 1,
                                                                              'charset_xml' => 1
                                                                            },
                                                                 'version' => {
                                                                              'values' => {
                                                                                          '1.0' => {}
                                                                                        }
                                                                            }
                                                               },
                                                   'scripting_language' => 'no',
                                                   'text' => 1
                                                 },
                                          'xml+cheetah' => {},
                                          'xml+django' => {},
                                          'xml+evoque' => {},
                                          'xml+jinja' => {},
                                          'xml+lasso' => {},
                                          'xml+mako' => {},
                                          'xml+myghty' => {},
                                          'xml+php' => {},
                                          'xml+ruby' => {},
                                          'xml+smarty' => {},
                                          'xml+spitfire' => {},
                                          'xml+velocity' => {},
                                          'xml-diff' => {},
                                          'xml-dtd' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common',
                                                       'params' => {
                                                                     'charset' => {
                                                                                  'charset_rfc7303' => 1,
                                                                                  'charset_xml' => 1
                                                                                }
                                                                   },
                                                       'text' => 1
                                                     },
                                          'xml-external-parsed-entity' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'common',
                                                                          'params' => {
                                                                                        'charset' => {
                                                                                                     'charset_rfc7303' => 1,
                                                                                                     'charset_xml' => 1
                                                                                                   }
                                                                                      },
                                                                          'text' => 1
                                                                        },
                                          'xml-patch+xml' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'xmpp+xml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                          'xneval' => {},
                                          'xop+xml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'xproc+xml' => {},
                                          'xquery' => {},
                                          'xrd+xml' => {
                                                       'params' => {
                                                                     'cid' => {},
                                                                     'https' => {},
                                                                     'nodefault_m' => {},
                                                                     'nodefault_p' => {},
                                                                     'nodefault_t' => {},
                                                                     'refs' => {},
                                                                     'saml' => {},
                                                                     'sep' => {},
                                                                     'trust' => {
                                                                                'obsolete' => 1
                                                                              },
                                                                     'uric' => {}
                                                                   }
                                                     },
                                          'xrds+xml' => {
                                                        'params' => {
                                                                      'cid' => {},
                                                                      'https' => {},
                                                                      'nodefault_m' => {},
                                                                      'nodefault_p' => {},
                                                                      'nodefault_t' => {},
                                                                      'refs' => {},
                                                                      'saml' => {},
                                                                      'sep' => {},
                                                                      'trust' => {
                                                                                 'obsolete' => 1
                                                                               },
                                                                      'uric' => {}
                                                                    }
                                                      },
                                          'xsl+xml' => {},
                                          'xslfo+xml' => {},
                                          'xslt+xml' => {
                                                        'iana' => 'permanent',
                                                        'params' => {
                                                                      'charset' => {}
                                                                    },
                                                        'styling' => 1,
                                                        'text' => 1
                                                      },
                                          'xspf+xml' => {},
                                          'xss-auditor-report' => {},
                                          'xv+xml' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'limited use'
                                                    },
                                          'yaml' => {
                                                    'text' => 1
                                                  },
                                          'yang' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'yang-data+json' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'yang-data+xml' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'yang-patch+json' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'yang-patch+xml' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                          'yin+xml' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                          'ynd.ms-pkipko' => {},
                                          'zip' => {
                                                   'iana' => 'permanent'
                                                 },
                                          'zip-compressed' => {},
                                          'zlib' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                          'zstd' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  }
                                        }
                         },
          'application-x' => {
                             'subtype' => {
                                            'geogebra-file' => {}
                                          }
                           },
          'archive' => {
                       'subtype' => {
                                      'zip' => {}
                                    }
                     },
          'attachment' => {
                          'subtype' => {
                                         'file' => {}
                                       }
                        },
          'audio' => {
                     'audiovideo' => 1,
                     'iana' => 'permanent',
                     'not_script' => 1,
                     'subtype' => {
                                    '1d-interleaved-parityfec' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                    '32kadpcm' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    '3gpp' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common',
                                              'params' => {
                                                            'codecs' => {}
                                                          }
                                            },
                                    '3gpp2' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common',
                                               'params' => {
                                                             'codecs' => {}
                                                           }
                                             },
                                    '8svx' => {},
                                    'aac' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'ac3' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'adpcm' => {},
                                    'aifc' => {},
                                    'aiff' => {},
                                    'amr' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'amr-wb' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                    'amr-wb+' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'aptx' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'asc' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'asf' => {},
                                    'atrac-advanced-lossless' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                    'atrac-x' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'atrac3' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                    'au' => {},
                                    'audible' => {},
                                    'avi' => {},
                                    'basic' => {
                                               'iana' => 'permanent'
                                             },
                                    'bv16' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'bv32' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'cleanmode' => {},
                                    'clearmode' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                    'cn' => {
                                            'iana' => 'permanent',
                                            'iana_intended_usage' => 'common'
                                          },
                                    'dat12' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                    'dls' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'dsr-es201108' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'dsr-es202050' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'dsr-es202211' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'dsr-es202212' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'dv' => {
                                            'iana' => 'permanent',
                                            'iana_intended_usage' => 'common'
                                          },
                                    'dvi4' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'eac3' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'echospeech' => {},
                                    'encaprtp' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'limited use'
                                                },
                                    'evrc' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'evrc-qcp' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    'evrc0' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                    'evrc1' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                    'evrcb' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                    'evrcb0' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                    'evrcb1' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                    'evrcnw' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                    'evrcnw0' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'evrcnw1' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'evrcwb' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                    'evrcwb0' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'evrcwb1' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'evs' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'example' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'limited use'
                                               },
                                    'flac' => {},
                                    'fwdred' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                    'g.722.1' => {},
                                    'g711-0' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                    'g719' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'g722' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'g7221' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                    'g723' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'g726-16' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'g726-24' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'g726-32' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'g726-40' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'g728' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'g729' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'g7291' => {
                                               'iana' => 'permanent'
                                             },
                                    'g729d' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                    'g729e' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                    'gsm' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'gsm-efr' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'gsm-hr-08' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                    'ilbc' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'imelody' => {},
                                    'ip-mr_v2.5' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                    'isac' => {},
                                    'it' => {},
                                    'karaoke' => {},
                                    'l16' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'l20' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'l24' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'l8' => {
                                            'iana' => 'permanent',
                                            'iana_intended_usage' => 'common'
                                          },
                                    'lpc' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'm' => {},
                                    'm4a' => {},
                                    'm4b' => {},
                                    'm4p' => {},
                                    'mad' => {},
                                    'madi' => {},
                                    'make' => {},
                                    'make.my.funk' => {},
                                    'mdz' => {},
                                    'med' => {},
                                    'melp' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'melp1200' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    'melp2400' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    'melp600' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'mid' => {},
                                    'midi' => {},
                                    'mobile-xmf' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                    'mod' => {},
                                    'module-xm' => {},
                                    'mp1' => {},
                                    'mp2' => {},
                                    'mp3' => {},
                                    'mp4' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'mp4a-latm' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                    'mpa' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'mpa-robust' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                    'mpeg' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'mpeg-url' => {},
                                    'mpeg2' => {},
                                    'mpeg3' => {},
                                    'mpeg4' => {},
                                    'mpeg4-generic' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                    'mpegurl' => {},
                                    'mpg' => {},
                                    'musepack' => {},
                                    'nspaudio' => {},
                                    'ogg' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common',
                                             'params' => {
                                                           'codecs' => {
                                                                       'values' => {
                                                                                   'speex' => {}
                                                                                 }
                                                                     }
                                                         }
                                           },
                                    'opus' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'parityfec' => {
                                                   'iana' => 'permanent'
                                                 },
                                    'pcma' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'pcma-wb' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'pcmu' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'pcmu-wb' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'playlist' => {},
                                    'prs.sid' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common',
                                                 'params' => {
                                                               'version' => {
                                                                            'values' => {
                                                                                        '1' => {},
                                                                                        '2' => {}
                                                                                      }
                                                                          }
                                                             }
                                               },
                                    'psid' => {},
                                    'qcelp' => {
                                               'iana' => 'permanent'
                                             },
                                    'qcp' => {},
                                    'raptorfec' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                    'red' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'rmf' => {},
                                    'rn-mpeg' => {},
                                    'rtp-enc-aescm128' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                    'rtp-midi' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    'rtploopback' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'limited use'
                                                   },
                                    'rtx' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    's-wav' => {},
                                    's3m' => {},
                                    'scpls' => {},
                                    'sfil' => {},
                                    'silk' => {},
                                    'smv' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'smv-qcp' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'smv0' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'songsafe' => {},
                                    'soundtrack' => {},
                                    'sp-midi' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'speex' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                    'sysex' => {},
                                    't140c' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                    't38' => {
                                             'iana' => 'permanent'
                                           },
                                    'telephone-event' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                    'tetra_acelp' => {
                                                     'iana' => 'provisional'
                                                   },
                                    'tone' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'tsp-audio' => {},
                                    'tsplayer' => {},
                                    'uemclip' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'ulpfec' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                    'unknown' => {},
                                    'usac' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'vdvi' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'vmr-wb' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                    'vnd.3gpp.iufp' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                    'vnd.4sb' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'vnd.adobe.soundbooth' => {},
                                    'vnd.audible.aax' => {},
                                    'vnd.audiokoz' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'vnd.celp' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    'vnd.cisco.nse' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'limited use'
                                                     },
                                    'vnd.cmles.radio-events' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'limited use'
                                                              },
                                    'vnd.cns.anp1' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'vnd.cns.inf1' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'vnd.dece.audio' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                    'vnd.digital-winds' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                    'vnd.dlna.adts' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                    'vnd.dolby.heaac.1' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'limited use'
                                                         },
                                    'vnd.dolby.heaac.2' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'limited use'
                                                         },
                                    'vnd.dolby.mlp' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                    'vnd.dolby.mps' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'limited use'
                                                     },
                                    'vnd.dolby.pl2' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                    'vnd.dolby.pl2x' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                    'vnd.dolby.pl2z' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                    'vnd.dolby.pulse.1' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                    'vnd.dra' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'vnd.dts' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'vnd.dts.hd' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                    'vnd.dvb.file' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'vnd.everad.plj' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                    'vnd.hns.audio' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'limited use'
                                                     },
                                    'vnd.lucent.voice' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                    'vnd.ms-playready.media.pya' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                    'vnd.nokia.mobile-xmf' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'limited use'
                                                            },
                                    'vnd.nortel.vbk' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'limited use'
                                                      },
                                    'vnd.nuera.ecelp4800' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                    'vnd.nuera.ecelp7470' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                    'vnd.nuera.ecelp9600' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                    'vnd.octel.sbc' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                    'vnd.pn-realaudio' => {},
                                    'vnd.presonus.multitrack' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                    'vnd.qcelp' => {
                                                   'iana' => 'permanent',
                                                   'obsolete' => 1
                                                 },
                                    'vnd.rhetorex.32kadpcm' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                    'vnd.rip' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'vnd.rn-mp3' => {},
                                    'vnd.rn-realaudio' => {
                                                          'params' => {
                                                                        'version' => {
                                                                                     'values' => {
                                                                                                 '3' => {}
                                                                                               }
                                                                                   }
                                                                      }
                                                        },
                                    'vnd.sealedmedia.softseal.mpeg' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                    'vnd.vmx.cvsd' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'vnd.wave' => {},
                                    'voc' => {},
                                    'vorbis' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                    'vorbis-config' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                    'voxware' => {},
                                    'wav' => {},
                                    'wave' => {},
                                    'webm' => {},
                                    'x-669-mod' => {},
                                    'x-8svx' => {},
                                    'x-aac' => {},
                                    'x-ac3' => {},
                                    'x-adbcm' => {},
                                    'x-adpcm' => {},
                                    'x-aifc' => {},
                                    'x-aiff' => {
                                                'params' => {
                                                              'version' => {
                                                                           'values' => {
                                                                                       '1.3' => {}
                                                                                     }
                                                                         }
                                                            }
                                              },
                                    'x-alaw-basic' => {},
                                    'x-amzaudio' => {},
                                    'x-amzxml' => {},
                                    'x-annodex' => {},
                                    'x-ape' => {},
                                    'x-arib-aiff' => {},
                                    'x-arib-mp3' => {},
                                    'x-arib-mpeg4-aac' => {},
                                    'x-arib-mpeg4-als' => {},
                                    'x-arib-romsound' => {},
                                    'x-au' => {},
                                    'x-background' => {},
                                    'x-bamba' => {},
                                    'x-basic' => {},
                                    'x-caf' => {},
                                    'x-chacha' => {},
                                    'x-cmf' => {},
                                    'x-dec-adbcm' => {},
                                    'x-dec-basic' => {},
                                    'x-ds2' => {},
                                    'x-dspeech' => {},
                                    'x-dss' => {},
                                    'x-dv' => {},
                                    'x-eac3' => {},
                                    'x-emod' => {},
                                    'x-epac' => {},
                                    'x-evrc1' => {},
                                    'x-evrcb' => {},
                                    'x-evrcb0' => {},
                                    'x-evrcb1' => {},
                                    'x-evrcwb' => {},
                                    'x-evrcwb0' => {},
                                    'x-evrcwb1' => {},
                                    'x-example' => {},
                                    'x-fasttracker-mod' => {},
                                    'x-flac' => {},
                                    'x-flac+ogg' => {},
                                    'x-fmaudio' => {},
                                    'x-ft2-mod' => {},
                                    'x-g.722.1' => {},
                                    'x-g7291' => {},
                                    'x-gsm' => {},
                                    'x-gus-patch' => {},
                                    'x-iriver-pla' => {},
                                    'x-isac' => {},
                                    'x-it' => {},
                                    'x-jam' => {},
                                    'x-karaoke' => {},
                                    'x-la-lms' => {},
                                    'x-la-lqt' => {},
                                    'x-liquid' => {},
                                    'x-liquid-file' => {},
                                    'x-liquid-secure' => {},
                                    'x-liveaudio' => {},
                                    'x-m4a' => {},
                                    'x-m4b' => {},
                                    'x-m4p' => {},
                                    'x-m4r' => {},
                                    'x-macaudio' => {},
                                    'x-make' => {},
                                    'x-make.my.funk' => {},
                                    'x-matroska' => {},
                                    'x-mei-aac' => {},
                                    'x-mid' => {},
                                    'x-midi' => {},
                                    'x-mikmod-uni' => {},
                                    'x-minipsf' => {},
                                    'x-mio' => {},
                                    'x-mo3' => {},
                                    'x-mod' => {},
                                    'x-monkeys-audio' => {},
                                    'x-mp2' => {},
                                    'x-mp3' => {},
                                    'x-mp4a' => {},
                                    'x-mpeg' => {},
                                    'x-mpeg-2' => {},
                                    'x-mpeg-3' => {},
                                    'x-mpeg2' => {},
                                    'x-mpeg3' => {},
                                    'x-mpegaudio' => {},
                                    'x-mpegurl' => {},
                                    'x-mpequrl' => {},
                                    'x-mpg' => {},
                                    'x-ms-asf' => {},
                                    'x-ms-asx' => {},
                                    'x-ms-wax' => {},
                                    'x-ms-wma' => {},
                                    'x-ms-wmv' => {},
                                    'x-multimate-mod' => {},
                                    'x-multitrack' => {},
                                    'x-musepack' => {},
                                    'x-musicnet-download' => {},
                                    'x-musicnet-stream' => {},
                                    'x-next' => {},
                                    'x-nficwmado0' => {},
                                    'x-nspaudio' => {},
                                    'x-ogg' => {},
                                    'x-ogg-flac' => {},
                                    'x-ogg-pcm' => {},
                                    'x-oggflac' => {},
                                    'x-oggpcm' => {},
                                    'x-oktalyzer-mod' => {},
                                    'x-oleobject' => {},
                                    'x-opus' => {},
                                    'x-opus+ogg' => {},
                                    'x-pac' => {},
                                    'x-pdxmidi' => {},
                                    'x-pdxvoice' => {},
                                    'x-pn-aiff' => {},
                                    'x-pn-au' => {},
                                    'x-pn-audibleaudio' => {},
                                    'x-pn-realaudio' => {},
                                    'x-pn-realaudio-plugin' => {},
                                    'x-pn-realvideo' => {},
                                    'x-pn-wav' => {},
                                    'x-pn-windows-acm' => {},
                                    'x-pn-windows-pcm' => {},
                                    'x-protracker-mod' => {},
                                    'x-psf' => {},
                                    'x-psflib' => {},
                                    'x-psid' => {},
                                    'x-real-audio' => {},
                                    'x-realaudio' => {},
                                    'x-realaudio-secure' => {},
                                    'x-red' => {},
                                    'x-riff' => {},
                                    'x-rmf' => {},
                                    'x-rogerwilco' => {},
                                    'x-s3m' => {},
                                    'x-sbc' => {},
                                    'x-sbi' => {},
                                    'x-scpls' => {},
                                    'x-sd2' => {},
                                    'x-sidtune' => {},
                                    'x-silk' => {},
                                    'x-smd' => {},
                                    'x-songsafe' => {},
                                    'x-speex' => {},
                                    'x-speex+ogg' => {},
                                    'x-st2-mod' => {},
                                    'x-st3-mod' => {},
                                    'x-startracker-mod' => {},
                                    'x-stm' => {},
                                    'x-taketracker-mod' => {},
                                    'x-toc' => {},
                                    'x-tsp-audio' => {},
                                    'x-tsplayer' => {},
                                    'x-tta' => {},
                                    'x-twinvq' => {},
                                    'x-twinvq-plugin' => {},
                                    'x-ulaw' => {},
                                    'x-vnd.audioexplosion.mjuicemediafile' => {},
                                    'x-vnd.audioexplosion.mjuidemedia' => {},
                                    'x-voc' => {},
                                    'x-vorbis' => {},
                                    'x-vorbis+ogg' => {},
                                    'x-voxware' => {},
                                    'x-wav' => {
                                               'params' => {
                                                             'version' => {
                                                                          'values' => {
                                                                                      '0 generic' => {},
                                                                                      '0 mpeg encoding' => {},
                                                                                      '0 pcm encoding' => {},
                                                                                      '0 waveformatextensible encoding' => {},
                                                                                      '1 generic' => {},
                                                                                      '1 mpeg encoding' => {},
                                                                                      '1 pcm encoding' => {},
                                                                                      '1 waveformatextensible encoding' => {},
                                                                                      '2 generic' => {},
                                                                                      '2 mpeg encoding' => {},
                                                                                      '2 pcm encoding' => {},
                                                                                      '2 waveformatextensible encoding' => {},
                                                                                      '2.0' => {},
                                                                                      '2.1' => {},
                                                                                      '2.2' => {}
                                                                                    }
                                                                        }
                                                           }
                                             },
                                    'x-wave' => {},
                                    'x-wavpack' => {},
                                    'x-wavpack-correction' => {},
                                    'x-webm' => {},
                                    'x-wma-10-professional' => {},
                                    'x-wma-drm' => {},
                                    'x-xi' => {},
                                    'x-xm' => {},
                                    'x-xmf' => {},
                                    'x-zdspcmusic' => {},
                                    'x-zipped-it' => {},
                                    'x-zipped-mod' => {},
                                    'xm' => {},
                                    'xmf0' => {},
                                    'xmf1' => {}
                                  }
                   },
          'auth' => {
                    'subtype' => {
                                   'sicily' => {}
                                 }
                  },
          'authorproject' => {
                             'subtype' => {
                                            'divx' => {}
                                          }
                           },
          'avro' => {
                    'subtype' => {
                                   'binary' => {}
                                 }
                  },
          'bin' => {
                   'subtype' => {
                                  'application' => {}
                                }
                 },
          'binary' => {
                      'subtype' => {
                                     'lzh' => {},
                                     'octet-stream' => {},
                                     'zip' => {}
                                   }
                    },
          'chemical' => {
                        'subtype' => {
                                       'kinemage' => {},
                                       'x-cdx' => {},
                                       'x-chem3d' => {},
                                       'x-chemdraw' => {},
                                       'x-cif' => {},
                                       'x-cmdf' => {},
                                       'x-cml' => {},
                                       'x-cow' => {},
                                       'x-csml' => {},
                                       'x-daylight-smiles' => {},
                                       'x-embl-dl-nucleotide' => {},
                                       'x-enbl-dl-nucleotide' => {},
                                       'x-gaussian-cube' => {},
                                       'x-gaussian-input' => {},
                                       'x-jcamp-dx' => {},
                                       'x-kinemage' => {},
                                       'x-mdl-molfile' => {},
                                       'x-mdl-rxn' => {},
                                       'x-mdl-rxnfile' => {},
                                       'x-mdl-tgf' => {},
                                       'x-mopac-input' => {},
                                       'x-pdb' => {
                                                  'obsolete' => 1
                                                },
                                       'x-questel-f1' => {},
                                       'x-questel-f1-query' => {},
                                       'x-spectra' => {},
                                       'x-spt' => {},
                                       'x-xyz' => {
                                                  'obsolete' => 1
                                                }
                                     }
                      },
          'coloreal' => {
                        'subtype' => {
                                       'embedded' => {}
                                     }
                      },
          'com.google.android.gms.fitness.data_type' => {},
          'content' => {
                       'subtype' => {
                                      'unknown' => {}
                                    }
                     },
          'database' => {
                        'subtype' => {
                                       'x-unknown' => {}
                                     }
                      },
          'defiant' => {
                       'subtype' => {
                                      'xsl-template' => {}
                                    }
                     },
          'document' => {
                        'subtype' => {
                                       'unknown' => {},
                                       'x-epub' => {}
                                     }
                      },
          'drawing' => {
                       'subtype' => {
                                      'dwf' => {
                                               'obsolete' => 1
                                             },
                                      'dwg' => {},
                                      'x-dwf' => {
                                                 'params' => {
                                                               'version' => {
                                                                            'values' => {
                                                                                        '6.0' => {}
                                                                                      }
                                                                          }
                                                             }
                                               },
                                      'x-dwf (old)' => {},
                                      'x-dxf' => {}
                                    }
                     },
          'dropload' => {
                        'subtype' => {
                                       'binary' => {}
                                     }
                      },
          'dsmcc-download' => {
                              'subtype' => {
                                             'jpeg' => {}
                                           }
                            },
          'dsmcc-file' => {
                          'subtype' => {
                                         'html' => {},
                                         'mpeg2-ps' => {}
                                       }
                        },
          'dsmcc-stream' => {
                            'subtype' => {
                                           'mpeg2-ts' => {}
                                         }
                          },
          'example' => {},
          'examples' => {
                        'iana' => 'permanent'
                      },
          'file' => {
                    'subtype' => {
                                   'executable' => {},
                                   'unknown' => {}
                                 }
                  },
          'flv-application' => {
                               'subtype' => {
                                              'octet-stream' => {}
                                            }
                             },
          'font' => {
                    'font' => 1,
                    'iana' => 'permanent',
                    'subtype' => {
                                   'collection' => {
                                                   'iana' => 'permanent'
                                                 },
                                   'eot' => {},
                                   'opentype' => {},
                                   'otf' => {
                                            'iana' => 'permanent'
                                          },
                                   'sfnt' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                   'truetype' => {},
                                   'ttf' => {
                                            'iana' => 'permanent',
                                            'iana_intended_usage' => 'common'
                                          },
                                   'type1' => {},
                                   'vnd.ms-fontobject' => {},
                                   'woff' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                   'woff2' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                   'x-bdf' => {},
                                   'x-dos' => {},
                                   'x-figlet' => {},
                                   'x-framemaker' => {},
                                   'x-hp-windows' => {},
                                   'x-libgrx' => {},
                                   'x-linux-psf' => {},
                                   'x-pcf' => {},
                                   'x-snf' => {},
                                   'x-speedo' => {},
                                   'x-sunos-news' => {},
                                   'x-tex' => {},
                                   'x-tex-tfm' => {},
                                   'x-vfont' => {},
                                   'x-woff' => {}
                                 }
                  },
          'gadget' => {
                      'subtype' => {
                                     'x-googlegadget' => {}
                                   }
                    },
          'graphics' => {
                        'subtype' => {
                                       'x-inventor' => {}
                                     }
                      },
          'gzip' => {
                    'subtype' => {
                                   'document' => {}
                                 }
                  },
          'httpd' => {
                     'subtype' => {
                                    'send-as-is' => {}
                                  }
                   },
          'i-world' => {
                       'subtype' => {
                                      'i-vrml' => {}
                                    }
                     },
          'image' => {
                     'iana' => 'permanent',
                     'image' => 1,
                     'not_script' => 1,
                     'subtype' => {
                                    'aces' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'amidraw' => {},
                                    'any' => {},
                                    'apng' => {},
                                    'ascii-art' => {},
                                    'avci' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'avcs' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'avi' => {},
                                    'avs' => {},
                                    'bci' => {},
                                    'bie' => {},
                                    'bmp' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common',
                                             'obsolete' => 1,
                                             'params' => {
                                                           'version' => {
                                                                        'values' => {
                                                                                    '1.0' => {},
                                                                                    '2.0' => {},
                                                                                    '3.0' => {},
                                                                                    '3.0 nt' => {},
                                                                                    '4.0' => {},
                                                                                    '5.0' => {}
                                                                                  }
                                                                      }
                                                         }
                                           },
                                    'c4' => {},
                                    'cals' => {},
                                    'cewavelet' => {},
                                    'cgm' => {
                                             'iana' => 'permanent',
                                             'params' => {
                                                           'version' => {
                                                                        'values' => {
                                                                                    '1' => {},
                                                                                    '2' => {},
                                                                                    '3' => {},
                                                                                    '4' => {}
                                                                                  }
                                                                      }
                                                         }
                                           },
                                    'cis-cid' => {},
                                    'cis-cod' => {},
                                    'cit' => {},
                                    'cmu-raster' => {
                                                    'obsolete' => 1
                                                  },
                                    'cmyk' => {},
                                    'cpi' => {},
                                    'cur' => {},
                                    'dcx' => {},
                                    'dejavu' => {},
                                    'dgn' => {},
                                    'dib' => {},
                                    'dicom+rle' => {},
                                    'dicom-rle' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                    'djvu' => {},
                                    'dvb.subtitle' => {},
                                    'emf' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'eps' => {},
                                    'example' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'limited use'
                                               },
                                    'fax' => {},
                                    'fax-g3' => {},
                                    'fif' => {},
                                    'fits' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'fli' => {},
                                    'florian' => {},
                                    'flv' => {},
                                    'g3fax' => {
                                               'iana' => 'permanent'
                                             },
                                    'gif' => {
                                             'iana' => 'permanent',
                                             'params' => {
                                                           'version' => {
                                                                        'values' => {
                                                                                    '87a' => {},
                                                                                    '89a' => {}
                                                                                  }
                                                                      }
                                                         }
                                           },
                                    'gradation' => {},
                                    'gray' => {},
                                    'hdf' => {},
                                    'heic' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'heic-sequence' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                    'heif' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'heif-sequence' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                    'hpgl' => {},
                                    'i-vrml' => {},
                                    'ico' => {},
                                    'icon' => {},
                                    'ief' => {
                                             'iana' => 'permanent'
                                           },
                                    'if' => {},
                                    'ifs' => {},
                                    'imagn' => {},
                                    'iw44' => {},
                                    'j2c' => {},
                                    'j2k' => {},
                                    'jb2' => {},
                                    'jbig' => {},
                                    'jls' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'jng' => {},
                                    'jp2' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'jpc' => {},
                                    'jpe' => {},
                                    'jpeg' => {
                                              'iana' => 'permanent',
                                              'params' => {
                                                            'version' => {
                                                                         'values' => {
                                                                                     '1.0' => {},
                                                                                     '1.00' => {},
                                                                                     '1.01' => {},
                                                                                     '1.02' => {},
                                                                                     '2.0' => {},
                                                                                     '2.1' => {},
                                                                                     '2.2' => {},
                                                                                     '2.2.1' => {}
                                                                                   }
                                                                       }
                                                          }
                                            },
                                    'jpeg2000' => {},
                                    'jpeg2000-image' => {},
                                    'jpg' => {},
                                    'jpm' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'jpx' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'jutvision' => {},
                                    'jxr' => {
                                             'iana' => 'provisional'
                                           },
                                    'ktx' => {
                                             'iana' => 'permanent'
                                           },
                                    'mac' => {},
                                    'map' => {},
                                    'miff' => {},
                                    'mil' => {},
                                    'mng' => {},
                                    'mono' => {},
                                    'mov' => {},
                                    'mpeg' => {},
                                    'ms-bmp' => {},
                                    'mtv' => {},
                                    'naplps' => {
                                                'iana' => 'permanent',
                                                'params' => {
                                                              'version' => {}
                                                            },
                                                'text' => 1
                                              },
                                    'nitf' => {},
                                    'ntf' => {},
                                    'openraster' => {},
                                    'pbm' => {},
                                    'pcd' => {},
                                    'pcx' => {},
                                    'pdf' => {},
                                    'pgf' => {},
                                    'photoshop' => {},
                                    'pic' => {},
                                    'pict' => {},
                                    'pipeg' => {},
                                    'pjpeg' => {},
                                    'pm' => {},
                                    'png' => {
                                             'iana' => 'permanent',
                                             'params' => {
                                                           'version' => {
                                                                        'values' => {
                                                                                    '1.0' => {},
                                                                                    '1.1' => {},
                                                                                    '1.2' => {}
                                                                                  }
                                                                      }
                                                         }
                                           },
                                    'portable-bitmap' => {},
                                    'postscript' => {},
                                    'prs.btif' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    'prs.pti' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'psd' => {},
                                    'pwg-raster' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                    'rad' => {},
                                    'rast' => {},
                                    'rgb' => {},
                                    'rgba' => {},
                                    'rla' => {},
                                    'rle' => {},
                                    'sgi' => {},
                                    'sun-raster' => {},
                                    'svg' => {},
                                    'svg+xml' => {
                                                 'iana' => 'permanent',
                                                 'params' => {
                                                               'charset' => {},
                                                               'version' => {
                                                                            'values' => {
                                                                                        '1.0' => {},
                                                                                        '1.1' => {}
                                                                                      }
                                                                          }
                                                             },
                                                 'text' => 1
                                               },
                                    'svg-xml' => {
                                                 'params' => {
                                                               'charset' => {}
                                                             },
                                                 'text' => 1
                                               },
                                    'svh' => {},
                                    't38' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'targa' => {
                                               'obsolete' => 1
                                             },
                                    'tdf' => {},
                                    'tga' => {},
                                    'tif' => {},
                                    'tiff' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common',
                                              'params' => {
                                                            'version' => {
                                                                         'values' => {
                                                                                     '1.0' => {},
                                                                                     '1.1' => {},
                                                                                     '1.3' => {},
                                                                                     '1.4' => {},
                                                                                     '2.0' => {},
                                                                                     '2.1' => {},
                                                                                     '2.2' => {}
                                                                                   }
                                                                       }
                                                          }
                                            },
                                    'tiff-fx' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'unknown' => {},
                                    'uyyu' => {},
                                    'vasa' => {},
                                    'vec' => {},
                                    'vid' => {},
                                    'viff' => {},
                                    'vn-svf' => {},
                                    'vnd' => {},
                                    'vnd-svf' => {},
                                    'vnd.adobe.photoshop' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                    'vnd.adobe.premiere' => {},
                                    'vnd.adobe.svg+xml' => {
                                                           'params' => {
                                                                         'charset' => {}
                                                                       },
                                                           'text' => 1
                                                         },
                                    'vnd.airzip.accelerator.azv' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                    'vnd.cns.inf2' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'vnd.dece.graphic' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                    'vnd.dgn' => {
                                                 'obsolete' => 1
                                               },
                                    'vnd.djvu' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    'vnd.dvb.subtitle' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                    'vnd.dwf' => {
                                                 'params' => {
                                                               'version' => {
                                                                            'values' => {
                                                                                        '6.0' => {}
                                                                                      }
                                                                          }
                                                             }
                                               },
                                    'vnd.dwg' => {
                                                 'iana' => 'permanent',
                                                 'params' => {
                                                               'version' => {
                                                                            'values' => {
                                                                                        '1.0' => {},
                                                                                        '1.2' => {},
                                                                                        '1.3' => {},
                                                                                        '1.4' => {},
                                                                                        '2.0' => {},
                                                                                        '2.1' => {},
                                                                                        '2.2' => {},
                                                                                        '2.5' => {},
                                                                                        '2.6' => {},
                                                                                        '2000-2002' => {},
                                                                                        '2004-2005' => {},
                                                                                        '2007-2008' => {},
                                                                                        '2010/2011/2012' => {},
                                                                                        '2013/2014' => {},
                                                                                        'r10' => {},
                                                                                        'r11/12' => {},
                                                                                        'r13' => {},
                                                                                        'r14' => {},
                                                                                        'r9' => {}
                                                                                      }
                                                                          }
                                                             }
                                               },
                                    'vnd.dxf' => {
                                                 'iana' => 'permanent',
                                                 'params' => {
                                                               'version' => {
                                                                            'values' => {
                                                                                        '1.0' => {},
                                                                                        '1.2' => {},
                                                                                        '1.3' => {},
                                                                                        '1.4' => {},
                                                                                        '2.0' => {},
                                                                                        '2.1' => {},
                                                                                        '2.2' => {},
                                                                                        '2.5' => {},
                                                                                        '2.6' => {},
                                                                                        '2000-2002' => {},
                                                                                        '2004-2005' => {},
                                                                                        '2004/2005/2006' => {},
                                                                                        '2007/2008/2009' => {},
                                                                                        '2010/2011/2012' => {},
                                                                                        '2013/2014' => {},
                                                                                        'generic' => {},
                                                                                        'r10' => {},
                                                                                        'r11/12' => {},
                                                                                        'r13' => {},
                                                                                        'r14' => {},
                                                                                        'r9' => {}
                                                                                      }
                                                                          }
                                                             }
                                               },
                                    'vnd.fastbidsheet' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                    'vnd.fpx' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'vnd.fst' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'vnd.fujixerox.edmics-mmr' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                    'vnd.fujixerox.edmics-rlc' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                    'vnd.globalgraphics.pgb' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'limited use'
                                                              },
                                    'vnd.glocalgraphics.pgb' => {},
                                    'vnd.microsoft.icon' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                    'vnd.mix' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common',
                                                 'params' => {
                                                               'version' => {
                                                                            'values' => {
                                                                                        '1.0' => {}
                                                                                      }
                                                                          }
                                                             }
                                               },
                                    'vnd.mozilla.apng' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                    'vnd.ms-modi' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                    'vnd.ms-photo' => {},
                                    'vnd.net-fpx' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                    'vnd.net.fpx' => {
                                                     'obsolete' => 1
                                                   },
                                    'vnd.phonecom.cache' => {},
                                    'vnd.radiance' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'vnd.rn-realflash' => {},
                                    'vnd.rn-realpix' => {},
                                    'vnd.sealed.png' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                    'vnd.sealedmedia.softseal.gif' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                    'vnd.sealedmedia.softseal.jpg' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                    'vnd.svf' => {
                                                 'iana' => 'permanent'
                                               },
                                    'vnd.swiftview-cals' => {},
                                    'vnd.swiftview-pcx' => {},
                                    'vnd.tencent.tap' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                    'vnd.up.wpng' => {},
                                    'vnd.valve.source.texture' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                    'vnd.wap.wbmp' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'vnd.xiff' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    'vnd.zbrush.pcx' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                    'wavelet' => {},
                                    'webp' => {},
                                    'wmf' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'x-3ds' => {},
                                    'x-adobe-dng' => {},
                                    'x-applix-graphic' => {},
                                    'x-applix-graphics' => {},
                                    'x-arib-png' => {},
                                    'x-autocad' => {},
                                    'x-bitmap' => {},
                                    'x-bmp' => {},
                                    'x-bpg' => {},
                                    'x-bzeps' => {},
                                    'x-cal' => {},
                                    'x-cals' => {},
                                    'x-canon-cr2' => {},
                                    'x-canon-crw' => {},
                                    'x-canon-raw' => {},
                                    'x-canvas-instructions+text' => {},
                                    'x-cgm' => {},
                                    'x-cif' => {},
                                    'x-cmu-rast' => {},
                                    'x-cmu-raster' => {},
                                    'x-cmx' => {},
                                    'x-compressed-xcf' => {},
                                    'x-coreldraw' => {},
                                    'x-coreldrawpattern' => {},
                                    'x-coreldrawtemplate' => {},
                                    'x-corelphotopaint' => {},
                                    'x-cpi' => {},
                                    'x-cpr' => {},
                                    'x-cur' => {},
                                    'x-dcraw' => {},
                                    'x-dcx' => {},
                                    'x-dds' => {},
                                    'x-dejavu' => {},
                                    'x-denso-bmp' => {},
                                    'x-dib' => {},
                                    'x-djvu' => {},
                                    'x-doc-wavelet' => {},
                                    'x-dpx' => {},
                                    'x-dwf' => {
                                               'params' => {
                                                             'version' => {
                                                                          'values' => {
                                                                                      '6.0' => {}
                                                                                    }
                                                                        }
                                                           }
                                             },
                                    'x-dwg' => {},
                                    'x-dxf' => {},
                                    'x-emf' => {
                                               'iana' => 'permanent',
                                               'obsolete' => 1,
                                               'params' => {
                                                             'version' => {
                                                                          'values' => {
                                                                                      '1.0' => {},
                                                                                      '2.0' => {},
                                                                                      '3.0' => {}
                                                                                    }
                                                                        }
                                                           }
                                             },
                                    'x-emz' => {},
                                    'x-eps' => {},
                                    'x-epson-erf' => {},
                                    'x-eri' => {},
                                    'x-example' => {},
                                    'x-exr' => {},
                                    'x-exv' => {},
                                    'x-fastbid2-fbs' => {},
                                    'x-fax-g3' => {},
                                    'x-fif' => {},
                                    'x-florian' => {},
                                    'x-flv' => {},
                                    'x-fpx' => {},
                                    'x-freehand' => {},
                                    'x-freehand5' => {},
                                    'x-freehand7' => {},
                                    'x-fuji-raf' => {},
                                    'x-fujifilm-raf' => {},
                                    'x-gzeps' => {},
                                    'x-gzip' => {},
                                    'x-hasselblad-3fr' => {},
                                    'x-hasselblad-fff' => {},
                                    'x-hpgl' => {},
                                    'x-icns' => {},
                                    'x-ico' => {},
                                    'x-icon' => {},
                                    'x-iff' => {},
                                    'x-ilbm' => {},
                                    'x-img' => {},
                                    'x-iw44' => {},
                                    'x-j2c' => {},
                                    'x-jb2' => {},
                                    'x-jbig2' => {},
                                    'x-jg' => {},
                                    'x-jng' => {},
                                    'x-jp2-codestream' => {},
                                    'x-jp2-container' => {},
                                    'x-jpeg' => {},
                                    'x-jpeg-proprietary' => {},
                                    'x-jpeg2000-image' => {},
                                    'x-jpg' => {},
                                    'x-jps' => {},
                                    'x-jutvision' => {},
                                    'x-kodak-dcr' => {},
                                    'x-kodak-k25' => {},
                                    'x-kodak-kdc' => {},
                                    'x-leica-rwl' => {},
                                    'x-lotusamideaw' => {},
                                    'x-lwo' => {},
                                    'x-lws' => {},
                                    'x-lytro-lfp' => {},
                                    'x-macpaint' => {},
                                    'x-macpict' => {},
                                    'x-mamiya-mef' => {},
                                    'x-mgx-dsf' => {},
                                    'x-mgx-emf' => {},
                                    'x-mgx-qsf' => {},
                                    'x-minolta-mrw' => {},
                                    'x-mng' => {},
                                    'x-mrsid' => {},
                                    'x-mrsid-image' => {},
                                    'x-ms-bmp' => {
                                                  'obsolete' => 1
                                                },
                                    'x-ms-bmpi' => {},
                                    'x-msod' => {},
                                    'x-niff' => {},
                                    'x-nikon-nef' => {},
                                    'x-nikon-nrw' => {},
                                    'x-olympus-orf' => {},
                                    'x-openraster' => {},
                                    'x-paintshoppro' => {},
                                    'x-panasonic-raw' => {},
                                    'x-panasonic-raw2' => {},
                                    'x-panasonic-rw2' => {},
                                    'x-pbm' => {},
                                    'x-pc-paintbrush' => {},
                                    'x-pcl-hp' => {},
                                    'x-pcx' => {},
                                    'x-pentax-pef' => {},
                                    'x-pgm' => {},
                                    'x-photo-cd' => {},
                                    'x-photoshop' => {},
                                    'x-pict' => {
                                                'params' => {
                                                              'version' => {
                                                                           'values' => {
                                                                                       '1.0' => {},
                                                                                       '2.0' => {}
                                                                                     }
                                                                         }
                                                            }
                                              },
                                    'x-pjpeg' => {},
                                    'x-png' => {},
                                    'x-portable-anymap' => {},
                                    'x-portable-arbitrarymap' => {},
                                    'x-portable-bitmap' => {},
                                    'x-portable-graymap' => {},
                                    'x-portable-greymap' => {},
                                    'x-portable-pixmap' => {},
                                    'x-ppm' => {},
                                    'x-psd' => {},
                                    'x-quicktime' => {},
                                    'x-raw' => {},
                                    'x-raw-adobe' => {},
                                    'x-raw-canon' => {},
                                    'x-raw-casio' => {},
                                    'x-raw-epson' => {},
                                    'x-raw-fuji' => {},
                                    'x-raw-hasselblad' => {},
                                    'x-raw-imacon' => {},
                                    'x-raw-kodak' => {},
                                    'x-raw-leaf' => {},
                                    'x-raw-logitech' => {},
                                    'x-raw-mamiya' => {},
                                    'x-raw-minolta' => {},
                                    'x-raw-nikon' => {},
                                    'x-raw-olympus' => {},
                                    'x-raw-panasonic' => {},
                                    'x-raw-pentax' => {},
                                    'x-raw-phaseone' => {},
                                    'x-raw-rawzor' => {},
                                    'x-raw-red' => {},
                                    'x-raw-sigma' => {},
                                    'x-raw-sony' => {},
                                    'x-rawzor' => {},
                                    'x-rgb' => {},
                                    'x-rle' => {},
                                    'x-samsung-srw' => {},
                                    'x-sgi' => {},
                                    'x-sgi-bw' => {},
                                    'x-sigma-x3f' => {},
                                    'x-skencil' => {},
                                    'x-sld' => {},
                                    'x-sony-arw' => {},
                                    'x-sony-sr2' => {},
                                    'x-sony-srf' => {},
                                    'x-sun-raster' => {},
                                    'x-svf' => {},
                                    'x-svg+xml-compressed' => {},
                                    'x-targa' => {},
                                    'x-tga' => {},
                                    'x-tif' => {},
                                    'x-tiff' => {},
                                    'x-tiff-big' => {},
                                    'x-up-bmp' => {},
                                    'x-up-wpng' => {},
                                    'x-vasa' => {},
                                    'x-vnd.adobe.air.bitmap' => {},
                                    'x-vnd.dgn' => {},
                                    'x-vsd' => {},
                                    'x-wavelet' => {},
                                    'x-webp' => {},
                                    'x-win-bitmap' => {},
                                    'x-win-bmp' => {},
                                    'x-win-metafile' => {},
                                    'x-windows-bitmap' => {},
                                    'x-windows-bmp' => {},
                                    'x-windows-icon' => {},
                                    'x-windows-meta' => {},
                                    'x-wmf' => {
                                               'iana' => 'permanent',
                                               'obsolete' => 1
                                             },
                                    'x-wordperfect-graphics' => {},
                                    'x-xbitmap' => {
                                                   'params' => {
                                                                 'charset' => {},
                                                                 'version' => {
                                                                              'values' => {
                                                                                          'x10' => {},
                                                                                          'x11' => {}
                                                                                        }
                                                                            }
                                                               },
                                                   'text' => 1
                                                 },
                                    'x-xbm' => {
                                               'params' => {
                                                             'charset' => {}
                                                           },
                                               'text' => 1
                                             },
                                    'x-xcf' => {},
                                    'x-xcursor' => {},
                                    'x-xfig' => {},
                                    'x-xpixmap' => {
                                                   'params' => {
                                                                 'version' => {
                                                                              'values' => {
                                                                                          'x10' => {}
                                                                                        }
                                                                            }
                                                               }
                                                 },
                                    'x-xpm' => {},
                                    'x-xres' => {},
                                    'x-xwd' => {},
                                    'x-xwindowdump' => {
                                                       'params' => {
                                                                     'version' => {
                                                                                  'values' => {
                                                                                              'x10' => {}
                                                                                            }
                                                                                }
                                                                   }
                                                     },
                                    'x.dicom+rle' => {},
                                    'x.djvu' => {},
                                    'x11' => {},
                                    'xbitmap' => {},
                                    'xbm' => {},
                                    'xcf' => {},
                                    'xiff' => {},
                                    'xiff2' => {},
                                    'xpm' => {},
                                    'yuv' => {}
                                  }
                   },
          'in' => {
                  'subtype' => {
                                 'share' => {}
                               }
                },
          'inode' => {
                     'subtype' => {
                                    'blockdevice' => {},
                                    'chardevice' => {},
                                    'directory' => {},
                                    'fifo' => {},
                                    'mount-point' => {},
                                    'socket' => {},
                                    'symlink' => {}
                                  }
                   },
          'interface' => {
                         'subtype' => {
                                        'x-winamp-skin' => {}
                                      }
                       },
          'internal' => {
                        'subtype' => {
                                       'draft' => {}
                                     }
                      },
          'java' => {
                    'subtype' => {
                                   '*' => {}
                                 }
                  },
          'koan' => {
                    'subtype' => {
                                   'x-skm' => {}
                                 }
                  },
          'magnus-internal' => {
                               'subtype' => {
                                              'cgi' => {},
                                              'headers' => {},
                                              'imagemap' => {},
                                              'parsed-html' => {},
                                              'rpt' => {}
                                            }
                             },
          'math' => {
                    'subtype' => {
                                   'mml' => {},
                                   'tex' => {}
                                 }
                  },
          'matter-transport' => {
                                'subtype' => {
                                               'sentient-life-form' => {}
                                             }
                              },
          'mce-text' => {
                        'subtype' => {
                                       'javascript' => {}
                                     }
                      },
          'message' => {
                       'composite' => 1,
                       'iana' => 'permanent',
                       'preferred_cte' => 'quoted-printable',
                       'subtype' => {
                                      'coffeepot' => {
                                                     'text' => 1
                                                   },
                                      'cpim' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'limited use'
                                              },
                                      'delivery-status' => {
                                                           'iana' => 'permanent'
                                                         },
                                      'disposition-notification' => {
                                                                    'iana' => 'permanent'
                                                                  },
                                      'example' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'limited use'
                                                 },
                                      'external-body' => {
                                                         'iana' => 'permanent',
                                                         'params' => {
                                                                       'access-type' => {},
                                                                       'expiration' => {},
                                                                       'permission' => {},
                                                                       'server' => {},
                                                                       'site' => {},
                                                                       'size' => {},
                                                                       'subject' => {},
                                                                       'url' => {}
                                                                     },
                                                         'text' => 1
                                                       },
                                      'feedback-report' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                      'global' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                      'global-delivery-status' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                      'global-disposition-notification' => {
                                                                           'iana' => 'permanent',
                                                                           'iana_intended_usage' => 'common'
                                                                         },
                                      'global-headers' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                      'html' => {},
                                      'http' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common',
                                                'params' => {
                                                              'msgtype' => {},
                                                              'version' => {}
                                                            }
                                              },
                                      'imdn+xml' => {
                                                    'iana' => 'permanent'
                                                  },
                                      'news' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'obsolete',
                                                'obsolete' => 1
                                              },
                                      'partial' => {
                                                   'iana' => 'permanent',
                                                   'params' => {
                                                                 'id' => {},
                                                                 'number' => {},
                                                                 'total' => {}
                                                               }
                                                 },
                                      'rfc822' => {
                                                  'iana' => 'permanent'
                                                },
                                      'rfc822-headers' => {},
                                      's-http' => {
                                                  'iana' => 'permanent',
                                                  'params' => {
                                                                'msgtype' => {},
                                                                'version' => {}
                                                              }
                                                },
                                      'sip' => {
                                               'iana' => 'permanent'
                                             },
                                      'sipfrag' => {
                                                   'iana' => 'permanent'
                                                 },
                                      'teapot' => {
                                                  'text' => 1
                                                },
                                      'tracking-status' => {
                                                           'iana' => 'permanent'
                                                         },
                                      'vnd.si.simp' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'obsolete',
                                                       'obsolete' => 1
                                                     },
                                      'vnd.wfa.wsc' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                      'x-emlx' => {},
                                      'x-example' => {},
                                      'x-gnu-rmail' => {},
                                      'x-netnews' => {}
                                    }
                     },
          'mforge' => {
                      'subtype' => {
                                     'x-mirage' => {}
                                   }
                    },
          'midi' => {
                    'subtype' => {
                                   'mid' => {}
                                 }
                  },
          'misc' => {
                    'subtype' => {
                                   'ultravox' => {}
                                 }
                  },
          'model' => {
                     'iana' => 'permanent',
                     'params' => {
                                 'dimension' => {},
                                 'state' => {}
                               },
                     'preferred_cte' => 'base64',
                     'subtype' => {
                                    '3mf' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'example' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'limited use'
                                               },
                                    'fx3d' => {},
                                    'gltf+json' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                    'gltf-binary' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                    'iges' => {
                                              'iana' => 'permanent',
                                              'params' => {
                                                            'version' => {
                                                                         'values' => {
                                                                                     '5.x' => {}
                                                                                   }
                                                                       }
                                                          }
                                            },
                                    'mesh' => {
                                              'iana' => 'permanent'
                                            },
                                    'stl' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'vnd.collada+xml' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                    'vnd.dwf' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common',
                                                 'params' => {
                                                               'version' => {
                                                                            'values' => {
                                                                                        '6.0' => {}
                                                                                      }
                                                                          }
                                                             }
                                               },
                                    'vnd.dwfx+xps' => {},
                                    'vnd.flatland.3dml' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                    'vnd.gdl' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'vnd.gs-gdl' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                    'vnd.gs.gdl' => {},
                                    'vnd.gtw' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'vnd.moml+xml' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'limited use'
                                                    },
                                    'vnd.mts' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'vnd.opengex' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                    'vnd.parasolid.transmit.binary' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                    'vnd.parasolid.transmit.text' => {
                                                                     'iana' => 'permanent',
                                                                     'iana_intended_usage' => 'common'
                                                                   },
                                    'vnd.rosette.annotated-data-model' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'limited use'
                                                                        },
                                    'vnd.usdz+zip' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'vnd.valve.source.compiled-map' => {
                                                                       'iana' => 'permanent',
                                                                       'iana_intended_usage' => 'common'
                                                                     },
                                    'vnd.vtu' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'vrml' => {
                                              'iana' => 'permanent',
                                              'params' => {
                                                            'version' => {
                                                                         'values' => {
                                                                                     '1.0' => {},
                                                                                     '2.0' => {}
                                                                                   }
                                                                       }
                                                          }
                                            },
                                    'x-chem-3d' => {},
                                    'x-example' => {},
                                    'x-pov' => {},
                                    'x-x3d+binary' => {},
                                    'x-x3d+vrml' => {},
                                    'x3d' => {},
                                    'x3d+binary' => {},
                                    'x3d+fastinfoset' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                    'x3d+vrml' => {},
                                    'x3d+xml' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'x3d-vrml' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                }
                                  }
                   },
          'more' => {
                    'subtype' => {
                                   'less' => {}
                                 }
                  },
          'mozilla.application' => {
                                   'subtype' => {
                                                  'cached-xul' => {}
                                                }
                                 },
          'multipart' => {
                           'composite' => 1,
                           'iana' => 'permanent',
                           'params' => {
                                         'boundary' => {
                                                         'required' => 1
                                                       }
                                       },
                           'preferred_cte' => 'quoted-printable',
                           'subtype' => {
                                          'alternative' => {
                                                           'iana' => 'permanent',
                                                           'params' => {
                                                                         'differences' => {}
                                                                       }
                                                         },
                                          'appledouble' => {
                                                           'iana' => 'permanent',
                                                           'params' => {
                                                                         'name' => {}
                                                                       }
                                                         },
                                          'byteranges' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                          'digest' => {
                                                      'iana' => 'permanent'
                                                    },
                                          'dvb.service' => {},
                                          'encrypted' => {
                                                         'iana' => 'permanent'
                                                       },
                                          'example' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'limited use'
                                                     },
                                          'foo' => {},
                                          'form-data' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                          'gedi-record' => {},
                                          'header-set' => {
                                                          'iana' => 'permanent'
                                                        },
                                          'mixed' => {
                                                     'iana' => 'permanent'
                                                   },
                                          'multilingual' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                          'parallel' => {
                                                        'iana' => 'permanent'
                                                      },
                                          'related' => {
                                                       'iana' => 'permanent'
                                                     },
                                          'report' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common',
                                                      'params' => {
                                                                    'report-type' => {}
                                                                  }
                                                    },
                                          'signed' => {
                                                      'iana' => 'permanent'
                                                    },
                                          'vnd.bint.med-plus' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'limited use'
                                                               },
                                          'voice-message' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                          'x-byteranges' => {},
                                          'x-example' => {},
                                          'x-gzip' => {},
                                          'x-mimepgp' => {},
                                          'x-mixed-replace' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                          'x-multi-encrypted' => {},
                                          'x-parallel' => {
                                                          'obsolete' => 1
                                                        },
                                          'x-sgml' => {},
                                          'x-tar' => {},
                                          'x-ustar' => {},
                                          'x-www-form-data' => {},
                                          'x-www-form-urlencoded' => {
                                                                     'obsolete' => 1
                                                                   },
                                          'x-zip' => {}
                                        },
                           'text' => 1
                         },
          'music' => {
                     'subtype' => {
                                    'crescendo' => {},
                                    'crescendo-encrypted' => {},
                                    'x-crescendo-encrypted' => {},
                                    'x-karaoke' => {}
                                  }
                   },
          'netscape' => {
                        'subtype' => {
                                       'source' => {},
                                       'telnet' => {},
                                       'tn3270' => {}
                                     }
                      },
          'octet' => {
                     'subtype' => {
                                    'stream' => {}
                                  }
                   },
          'paleovu' => {
                       'subtype' => {
                                      'x-pv' => {}
                                    }
                     },
          'plain' => {
                     'subtype' => {
                                    'text' => {}
                                  }
                   },
          'plugin' => {
                      'subtype' => {
                                     'listenup' => {},
                                     'talker' => {},
                                     'wanimate' => {},
                                     'x-myvoice' => {},
                                     'x-theorist' => {}
                                   }
                    },
          'qpplication' => {
                           'subtype' => {
                                          'wasm' => {}
                                        }
                         },
          'security' => {
                        'subtype' => {
                                       'remote-passphrase' => {}
                                     }
                      },
          'sound' => {
                     'subtype' => {
                                    'aiff' => {}
                                  }
                   },
          'text' => {
                    'iana' => 'permanent',
                    'preferred_cte' => 'quoted-printable',
                    'subtype' => {
                                   '1d-interleaved-parityfec' => {
                                                                 'iana' => 'permanent',
                                                                 'iana_intended_usage' => 'common'
                                                               },
                                   '_moz_htmlcontext' => {},
                                   '_moz_htmlinfo' => {},
                                   'abiword' => {},
                                   'act' => {},
                                   'actionscript' => {},
                                   'actionscript3' => {},
                                   'apl' => {},
                                   'asp' => {},
                                   'aspdotnet' => {},
                                   'basic' => {},
                                   'bib' => {},
                                   'boolean' => {},
                                   'bss' => {},
                                   'c' => {},
                                   'c#' => {
                                           'scripting_language' => 'yes'
                                         },
                                   'cache' => {
                                              'scripting_language' => 'yes'
                                            },
                                   'cache-manifest' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                   'calendar' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common',
                                                 'params' => {
                                                               'charset' => {},
                                                               'component' => {},
                                                               'method' => {},
                                                               'optinfo' => {}
                                                             }
                                               },
                                   'calender' => {},
                                   'cas' => {},
                                   'cdf' => {
                                            'text' => 1
                                          },
                                   'cloud-boothook' => {},
                                   'cloud-config' => {},
                                   'cloud-config-archive' => {},
                                   'cmd' => {},
                                   'cmif' => {},
                                   'cmml' => {},
                                   'cobol' => {
                                              'scripting_language' => 'yes'
                                            },
                                   'coffeescript' => {},
                                   'comma-separated-values' => {
                                                               'obsolete' => 1
                                                             },
                                   'common-lisp' => {
                                                    'scripting_language' => 'yes'
                                                  },
                                   'cpp' => {},
                                   'css' => {
                                            'iana' => 'permanent',
                                            'iana_intended_usage' => 'common',
                                            'params' => {
                                                          'charset' => {}
                                                        },
                                            'styling' => 1
                                          },
                                   'css+django' => {},
                                   'css+genshi' => {},
                                   'css+jinja' => {},
                                   'css+lasso' => {},
                                   'css+mako' => {},
                                   'css+myghty' => {},
                                   'css+php' => {},
                                   'css+ruby' => {},
                                   'css+smarty' => {},
                                   'csv' => {
                                            'iana' => 'permanent',
                                            'iana_intended_usage' => 'common',
                                            'params' => {
                                                          'charset' => {},
                                                          'header' => {}
                                                        }
                                          },
                                   'csv-schema' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                   'dif+xml' => {},
                                   'directory' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common',
                                                  'obsolete' => 1,
                                                  'params' => {
                                                                'profile' => {}
                                                              }
                                                },
                                   'dlm' => {},
                                   'dns' => {
                                            'iana' => 'permanent',
                                            'iana_intended_usage' => 'limited use'
                                          },
                                   'download' => {},
                                   'dsssl' => {},
                                   'dvb.subtitle' => {},
                                   'dvb.teletext' => {},
                                   'dvb.utf8' => {},
                                   'ecmascript' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'obsolete',
                                                   'obsolete' => 1,
                                                   'params' => {
                                                                 'charset' => {},
                                                                 'version' => {}
                                                               },
                                                   'scripting_language' => 'javascript'
                                                 },
                                   'encaprtp' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'limited use'
                                               },
                                   'english' => {},
                                   'enriched' => {
                                                 'iana' => 'permanent',
                                                 'params' => {
                                                               'charset' => {}
                                                             }
                                               },
                                   'event-stream' => {},
                                   'example' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'limited use'
                                              },
                                   'ftp-dir' => {},
                                   'ftp-dir-listing' => {},
                                   'fwdred' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                   'gettext' => {},
                                   'goml' => {},
                                   'google-video-pointer' => {},
                                   'gpx' => {
                                            'params' => {
                                                          'charset' => {
                                                                       'charset_xml' => 1
                                                                     }
                                                        },
                                            'text' => 1
                                          },
                                   'grammar-ref-list' => {
                                                         'iana' => 'permanent'
                                                       },
                                   'gss' => {},
                                   'h323' => {},
                                   'haxe' => {},
                                   'hjson' => {},
                                   'hnf' => {},
                                   'html' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common',
                                             'params' => {
                                                           'charset' => {},
                                                           'level' => {},
                                                           'version' => {
                                                                        'values' => {
                                                                                    '2.0' => {},
                                                                                    '3.2' => {},
                                                                                    '4.0' => {},
                                                                                    '4.01' => {},
                                                                                    '5' => {}
                                                                                  }
                                                                      }
                                                         }
                                           },
                                   'html+cheetah' => {},
                                   'html+django' => {},
                                   'html+evoque' => {},
                                   'html+genshi' => {},
                                   'html+handlebars' => {},
                                   'html+jinja' => {},
                                   'html+lasso' => {},
                                   'html+mako' => {},
                                   'html+myghty' => {},
                                   'html+ruby' => {},
                                   'html+smarty' => {},
                                   'html+spitfire' => {},
                                   'html+twig' => {},
                                   'html+velocity' => {},
                                   'htmlr' => {},
                                   'ico' => {},
                                   'idl' => {},
                                   'inf' => {},
                                   'ipf' => {},
                                   'iuls' => {},
                                   'jade' => {},
                                   'java' => {},
                                   'javascript' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'obsolete',
                                                   'params' => {
                                                                 'charset' => {},
                                                                 'e4x' => {},
                                                                 'version' => {}
                                                               },
                                                   'scripting_language' => 'javascript'
                                                 },
                                   'javascript+cheetah' => {},
                                   'javascript+django' => {},
                                   'javascript+genshi' => {},
                                   'javascript+jinja' => {},
                                   'javascript+json' => {},
                                   'javascript+lasso' => {},
                                   'javascript+mako' => {},
                                   'javascript+mygthy' => {},
                                   'javascript+php' => {},
                                   'javascript+ruby' => {},
                                   'javascript+smarty' => {},
                                   'javascript+spitfire' => {},
                                   'javascript1.0' => {
                                                      'obsolete' => 1,
                                                      'params' => {
                                                                    'charset' => {}
                                                                  },
                                                      'scripting_language' => 'javascript'
                                                    },
                                   'javascript1.1' => {
                                                      'obsolete' => 1,
                                                      'params' => {
                                                                    'charset' => {}
                                                                  },
                                                      'scripting_language' => 'javascript'
                                                    },
                                   'javascript1.2' => {
                                                      'obsolete' => 1,
                                                      'params' => {
                                                                    'charset' => {}
                                                                  },
                                                      'scripting_language' => 'javascript'
                                                    },
                                   'javascript1.3' => {
                                                      'obsolete' => 1,
                                                      'params' => {
                                                                    'charset' => {}
                                                                  },
                                                      'scripting_language' => 'javascript'
                                                    },
                                   'javascript1.4' => {
                                                      'obsolete' => 1,
                                                      'params' => {
                                                                    'charset' => {}
                                                                  },
                                                      'scripting_language' => 'javascript'
                                                    },
                                   'javascript1.5' => {
                                                      'obsolete' => 1,
                                                      'params' => {
                                                                    'charset' => {}
                                                                  },
                                                      'scripting_language' => 'javascript'
                                                    },
                                   'jcr-cnd' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                   'jquery' => {},
                                   'js' => {},
                                   'jscript' => {
                                                'obsolete' => 1,
                                                'params' => {
                                                              'charset' => {}
                                                            },
                                                'scripting_language' => 'javascript'
                                              },
                                   'jscript.encode' => {
                                                       'scripting_language' => 'yes'
                                                     },
                                   'jsgf' => {},
                                   'json' => {
                                             'text' => 1
                                           },
                                   'jss' => {
                                            'styling' => 1
                                          },
                                   'jsss' => {},
                                   'jsx' => {},
                                   'juttle' => {},
                                   'kal' => {},
                                   'kendo-tmpl' => {},
                                   'ldif' => {},
                                   'less' => {},
                                   'limbo' => {},
                                   'livescript' => {
                                                   'obsolete' => 1,
                                                   'params' => {
                                                                 'charset' => {}
                                                               },
                                                   'scripting_language' => 'javascript'
                                                 },
                                   'logo' => {},
                                   'markdown' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                   'mathml' => {},
                                   'mathml-renderer' => {},
                                   'mathml-rendererb' => {},
                                   'matlab' => {},
                                   'mcf' => {},
                                   'mdl' => {},
                                   'microsoft-resx' => {},
                                   'mirc' => {},
                                   'mizar' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                   'mp4' => {},
                                   'mpml-basic-layout' => {},
                                   'mustache' => {},
                                   'n-triples' => {},
                                   'n3' => {
                                           'iana' => 'permanent',
                                           'iana_intended_usage' => 'common'
                                         },
                                   'ncl' => {},
                                   'nfo' => {
                                            'iana' => 'provisional'
                                          },
                                   'ng-template' => {},
                                   'nginx' => {},
                                   'ntriples' => {},
                                   'octave' => {},
                                   'odin' => {},
                                   'ofx' => {},
                                   'oobhtml' => {
                                                'obsolete' => 1,
                                                'params' => {
                                                              'markup' => {},
                                                              'oobcrc' => {},
                                                              'oobver' => {}
                                                            }
                                              },
                                   'os-data' => {},
                                   'os-template' => {},
                                   'owl-manchester' => {},
                                   'parameters' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                   'parityfec' => {
                                                  'iana' => 'permanent'
                                                },
                                   'part-handler' => {},
                                   'pascal' => {},
                                   'pdf' => {},
                                   'perl' => {},
                                   'perlscript' => {
                                                   'scripting_language' => 'yes'
                                                 },
                                   'php' => {
                                            'scripting_language' => 'yes'
                                          },
                                   'ping' => {},
                                   'plain' => {
                                              'iana' => 'permanent',
                                              'params' => {
                                                            'charset' => {},
                                                            'charset-edition' => {},
                                                            'charset-extension' => {},
                                                            'format' => {}
                                                          },
                                              'scripting_language' => 'no'
                                            },
                                   'plain-bas' => {},
                                   'pod' => {},
                                   'provenance-notation' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                   'prs.fallenstein.rst' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                   'prs.lines.tag' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                   'prs.prop.logic' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                   'pson' => {},
                                   'python' => {
                                               'scripting_language' => 'yes'
                                             },
                                   'qif' => {},
                                   'raptorfec' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                   'rdf' => {},
                                   'rdf+n3' => {},
                                   'rdf+turtle' => {},
                                   'red' => {
                                            'iana' => 'permanent',
                                            'iana_intended_usage' => 'common'
                                          },
                                   'rfc822' => {},
                                   'rfc822-headers' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                   'richtext' => {
                                                 'iana' => 'permanent',
                                                 'params' => {
                                                               'charset' => {}
                                                             }
                                               },
                                   'rocketscript' => {},
                                   'rsl' => {},
                                   'rss' => {},
                                   'rtf' => {
                                            'iana' => 'permanent',
                                            'params' => {
                                                          'version' => {
                                                                       'values' => {
                                                                                   '1.0-1.4' => {},
                                                                                   '1.1' => {},
                                                                                   '1.2' => {},
                                                                                   '1.3' => {},
                                                                                   '1.4' => {},
                                                                                   '1.5-1.6' => {},
                                                                                   '1.6' => {},
                                                                                   '1.7' => {},
                                                                                   '1.8' => {},
                                                                                   '1.9' => {}
                                                                                 }
                                                                     }
                                                        }
                                          },
                                   'rtp-enc-aescm128' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                   'rtploopback' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'limited use'
                                                  },
                                   'rtx' => {
                                            'iana' => 'permanent',
                                            'iana_intended_usage' => 'common'
                                          },
                                   'ruby' => {},
                                   'ruby-script' => {},
                                   'rubyscript' => {
                                                   'scripting_language' => 'yes'
                                                 },
                                   'rust' => {},
                                   's' => {},
                                   's-plus' => {},
                                   'sas' => {},
                                   'scilab' => {},
                                   'scriplet' => {},
                                   'script' => {},
                                   'scriptlet' => {},
                                   'sgml' => {
                                             'iana' => 'permanent',
                                             'params' => {
                                                           'charset' => {},
                                                           'sgml-bctf' => {},
                                                           'sgml-boot' => {}
                                                         }
                                           },
                                   'shex' => {},
                                   'site' => {},
                                   'sitemap' => {},
                                   'slim' => {},
                                   'smali' => {},
                                   'smil-basic' => {},
                                   'smil-basic-layout' => {},
                                   'sms' => {},
                                   'spice' => {},
                                   'spreadsheet' => {},
                                   'sql' => {
                                            'scripting_language' => 'yes'
                                          },
                                   'stata' => {},
                                   'strings' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                   'stylesheet' => {},
                                   'stylus' => {},
                                   'supercollider' => {},
                                   'swig' => {},
                                   't-time' => {},
                                   't140' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                   'tab-separated-values' => {
                                                             'iana' => 'permanent'
                                                           },
                                   'tcl' => {
                                            'scripting_language' => 'yes'
                                          },
                                   'template' => {},
                                   'teon' => {},
                                   'texmacs' => {},
                                   'tiscript' => {
                                                 'scripting_language' => 'yes'
                                               },
                                   'troff' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                   'tsv' => {},
                                   'turtle' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                   'txt' => {},
                                   'typescript' => {},
                                   'typescript-jsx' => {},
                                   'ulpfec' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                   'unicode' => {},
                                   'upstart-job' => {},
                                   'uri-list' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'limited use'
                                               },
                                   'url' => {},
                                   'url-list' => {},
                                   'vb' => {
                                           'scripting_language' => 'yes'
                                         },
                                   'vbs' => {
                                            'scripting_language' => 'yes'
                                          },
                                   'vbscript' => {
                                                 'scripting_language' => 'yes'
                                               },
                                   'vbscript.encode' => {
                                                        'scripting_language' => 'yes'
                                                      },
                                   'vcalendar' => {},
                                   'vcard' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                   'vcsswg' => {},
                                   'velocity' => {},
                                   'vnd.a' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                   'vnd.abc' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                   'vnd.ascii-art' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                   'vnd.csr' => {},
                                   'vnd.curl' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                   'vnd.curl.2.0' => {},
                                   'vnd.curl.dcurl' => {},
                                   'vnd.curl.mcurl' => {},
                                   'vnd.curl.scurl' => {},
                                   'vnd.curl.surge' => {},
                                   'vnd.debian.copyright' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'limited use'
                                                           },
                                   'vnd.dmclientscript' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                   'vnd.dvb.subtitle' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                   'vnd.esmertec.theme-descriptor' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'limited use'
                                                                    },
                                   'vnd.flatland.3dml' => {
                                                          'obsolete' => 1
                                                        },
                                   'vnd.fly' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                   'vnd.fmi.flexstor' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'limited use'
                                                       },
                                   'vnd.gml' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                   'vnd.graphviz' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                   'vnd.hgl' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                   'vnd.in3d.3dml' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                   'vnd.in3d.spot' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                   'vnd.iptc.anpa' => {},
                                   'vnd.iptc.newsml' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                   'vnd.iptc.nitf' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                   'vnd.latex-z' => {
                                                    'iana' => 'permanent'
                                                  },
                                   'vnd.motorola.reflex' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'common'
                                                          },
                                   'vnd.ms-mediapackage' => {
                                                            'iana' => 'permanent'
                                                          },
                                   'vnd.ms-word' => {},
                                   'vnd.net2phone.commcenter.command' => {
                                                                         'iana' => 'permanent',
                                                                         'iana_intended_usage' => 'limited use'
                                                                       },
                                   'vnd.radisys.msml-basic-layout' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                   'vnd.rn-realtext' => {},
                                   'vnd.rn-realtext3d' => {},
                                   'vnd.si.uricatalogue' => {
                                                            'iana' => 'permanent',
                                                            'iana_intended_usage' => 'limited use',
                                                            'obsolete' => 1
                                                          },
                                   'vnd.sun.j2me.app-descriptor' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'limited use'
                                                                  },
                                   'vnd.trolltech.linguist' => {
                                                               'iana' => 'permanent',
                                                               'iana_intended_usage' => 'common'
                                                             },
                                   'vnd.viewcvs-markup' => {},
                                   'vnd.wap.co' => {},
                                   'vnd.wap.connectivility-xml' => {},
                                   'vnd.wap.si' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                   'vnd.wap.sl' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                   'vnd.wap.wml' => {
                                                    'iana' => 'permanent',
                                                    'iana_intended_usage' => 'common'
                                                  },
                                   'vnd.wap.wmlscript' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                   'vnd.wordperfect' => {},
                                   'vtt' => {},
                                   'webviewhtml' => {},
                                   'wiki' => {},
                                   'wml' => {},
                                   'wreq' => {},
                                   'x-abap' => {},
                                   'x-abc' => {},
                                   'x-abnf' => {},
                                   'x-actionscript' => {},
                                   'x-actionscript3' => {},
                                   'x-ada' => {},
                                   'x-adasrc' => {},
                                   'x-agda' => {},
                                   'x-alloy' => {},
                                   'x-ambienttalk' => {},
                                   'x-apacheconf' => {},
                                   'x-apple-binscii' => {},
                                   'x-apple-macintalk' => {},
                                   'x-applescript' => {},
                                   'x-arduino' => {},
                                   'x-ascii-art' => {},
                                   'x-ascii-html' => {},
                                   'x-ascii-plain' => {},
                                   'x-asciidoc' => {},
                                   'x-asm' => {},
                                   'x-asp' => {},
                                   'x-aspectj' => {},
                                   'x-assembly' => {},
                                   'x-asterisk' => {},
                                   'x-astromark' => {},
                                   'x-asymptote' => {},
                                   'x-audiosoft-intra' => {},
                                   'x-authors' => {},
                                   'x-autohotkey' => {},
                                   'x-autoit' => {},
                                   'x-ave' => {},
                                   'x-awk' => {},
                                   'x-basic' => {},
                                   'x-bat' => {},
                                   'x-bb' => {},
                                   'x-bbcode' => {},
                                   'x-bibtex' => {},
                                   'x-bison' => {},
                                   'x-bmx' => {},
                                   'x-bnf' => {},
                                   'x-boo' => {},
                                   'x-brainfuck' => {},
                                   'x-c' => {},
                                   'x-c++' => {},
                                   'x-c++hdr' => {},
                                   'x-c++src' => {},
                                   'x-c-objdump' => {},
                                   'x-c-source' => {},
                                   'x-cache-manifest' => {},
                                   'x-calendar' => {},
                                   'x-cassandra' => {},
                                   'x-cdf' => {
                                              'text' => 1
                                            },
                                   'x-ceylon' => {},
                                   'x-cgi' => {},
                                   'x-chaiscript' => {},
                                   'x-changelog' => {},
                                   'x-chdr' => {},
                                   'x-cirru' => {},
                                   'x-clay' => {},
                                   'x-clojure' => {},
                                   'x-clojurescript' => {},
                                   'x-cmake' => {},
                                   'x-cmml' => {},
                                   'x-co-desc' => {},
                                   'x-cobol' => {},
                                   'x-coffeescript' => {},
                                   'x-coffescript' => {},
                                   'x-coldfusion' => {},
                                   'x-comma-separated-values' => {},
                                   'x-common-lisp' => {},
                                   'x-component' => {},
                                   'x-component-pascal' => {},
                                   'x-conf' => {},
                                   'x-config' => {},
                                   'x-copying' => {},
                                   'x-coq' => {},
                                   'x-cpp' => {},
                                   'x-cpp-objdump' => {},
                                   'x-cpp-source' => {},
                                   'x-credits' => {},
                                   'x-crocsrc' => {},
                                   'x-crontab' => {},
                                   'x-cross-domain-policy' => {
                                                              'text' => 1
                                                            },
                                   'x-cryptol' => {},
                                   'x-crystal' => {},
                                   'x-csh' => {},
                                   'x-csharp' => {},
                                   'x-csharpsrc' => {},
                                   'x-csrc' => {},
                                   'x-css-cmml' => {},
                                   'x-css-inline' => {},
                                   'x-csv' => {},
                                   'x-cuda' => {},
                                   'x-cvsweb-markup' => {},
                                   'x-cython' => {},
                                   'x-d' => {},
                                   'x-d-objdump' => {},
                                   'x-dart' => {},
                                   'x-dcl' => {},
                                   'x-dg' => {},
                                   'x-diff' => {},
                                   'x-django' => {},
                                   'x-dockerfile' => {},
                                   'x-dockerfile-config' => {},
                                   'x-dos-batch' => {},
                                   'x-dot-template' => {},
                                   'x-dpatch' => {},
                                   'x-dsl' => {},
                                   'x-dsrc' => {},
                                   'x-dtd' => {},
                                   'x-duel' => {},
                                   'x-dylan' => {},
                                   'x-dylan-console' => {},
                                   'x-dylan-lid' => {},
                                   'x-earl-grey' => {},
                                   'x-easytrieve' => {},
                                   'x-ebnf' => {},
                                   'x-echdr' => {},
                                   'x-ecl' => {},
                                   'x-ecmascript' => {
                                                     'obsolete' => 1,
                                                     'params' => {
                                                                   'charset' => {}
                                                                 },
                                                     'scripting_language' => 'javascript'
                                                   },
                                   'x-ecsrc' => {},
                                   'x-eiffel' => {},
                                   'x-ejs-template' => {},
                                   'x-elisp' => {},
                                   'x-elixir' => {},
                                   'x-elixir-shellsession' => {},
                                   'x-elm' => {},
                                   'x-emacs-lisp' => {},
                                   'x-email' => {},
                                   'x-emelody' => {},
                                   'x-english' => {},
                                   'x-erl-shellsession' => {},
                                   'x-erlang' => {},
                                   'x-errorlist' => {},
                                   'x-estraier-draft' => {},
                                   'x-event-stream' => {},
                                   'x-example' => {},
                                   'x-expect' => {},
                                   'x-ez80' => {},
                                   'x-ezhil' => {},
                                   'x-factor' => {},
                                   'x-fancysrc' => {},
                                   'x-fcl' => {},
                                   'x-feature' => {},
                                   'x-felix' => {},
                                   'x-flatline' => {},
                                   'x-forth' => {},
                                   'x-fortran' => {},
                                   'x-fsharp' => {},
                                   'x-game-map' => {},
                                   'x-gap' => {},
                                   'x-gas' => {},
                                   'x-generic' => {},
                                   'x-genie' => {},
                                   'x-genshi' => {},
                                   'x-gettext' => {},
                                   'x-gettext-translation' => {},
                                   'x-gettext-translation-template' => {},
                                   'x-gherkin' => {},
                                   'x-github-pull-request' => {},
                                   'x-glsl-fs' => {},
                                   'x-glslsrc' => {},
                                   'x-gnuplot' => {},
                                   'x-go' => {},
                                   'x-gooddata-cl' => {},
                                   'x-gooddata-maql' => {},
                                   'x-google-video-pointer' => {},
                                   'x-gosrc' => {},
                                   'x-gosu' => {},
                                   'x-gosu-template' => {},
                                   'x-gql' => {},
                                   'x-groovy' => {},
                                   'x-gss' => {},
                                   'x-gtkrc' => {},
                                   'x-gwt-rpc' => {},
                                   'x-h' => {},
                                   'x-h2h' => {},
                                   'x-h2h+html' => {},
                                   'x-h323' => {},
                                   'x-haml' => {},
                                   'x-handlebars-template' => {},
                                   'x-haskell' => {},
                                   'x-hatena-syntax' => {},
                                   'x-haxe' => {},
                                   'x-hdml' => {},
                                   'x-hive' => {},
                                   'x-hnf' => {},
                                   'x-hsail' => {},
                                   'x-html' => {},
                                   'x-html-insertion' => {},
                                   'x-html-srcdoc' => {},
                                   'x-html-template' => {},
                                   'x-htmlh' => {},
                                   'x-hx' => {},
                                   'x-hxml' => {},
                                   'x-hy' => {},
                                   'x-hybris' => {},
                                   'x-idl' => {},
                                   'x-idris' => {},
                                   'x-imagemap' => {},
                                   'x-imelody' => {},
                                   'x-include-once-url' => {},
                                   'x-include-url' => {},
                                   'x-info' => {},
                                   'x-ini' => {},
                                   'x-ini-file' => {},
                                   'x-install' => {},
                                   'x-iokesrc' => {},
                                   'x-iosrc' => {},
                                   'x-iptables' => {},
                                   'x-irclog' => {},
                                   'x-isabelle' => {},
                                   'x-iuls' => {},
                                   'x-j' => {},
                                   'x-jade' => {},
                                   'x-java' => {},
                                   'x-java-properties' => {},
                                   'x-java-source' => {},
                                   'x-javascript' => {
                                                     'obsolete' => 1,
                                                     'params' => {
                                                                   'charset' => {}
                                                                 },
                                                     'scripting_language' => 'javascript'
                                                   },
                                   'x-javascript+cheetah' => {},
                                   'x-javascript+django' => {},
                                   'x-javascript+genshi' => {},
                                   'x-javascript+jinja' => {},
                                   'x-javascript+lasso' => {},
                                   'x-javascript+mako' => {},
                                   'x-javascript+myghty' => {},
                                   'x-javascript+php' => {},
                                   'x-javascript+ruby' => {},
                                   'x-javascript+smarty' => {},
                                   'x-javascript+spitfire' => {},
                                   'x-jbst' => {},
                                   'x-jcl' => {},
                                   'x-jdoc-format' => {},
                                   'x-jquery-tmpl' => {},
                                   'x-js' => {},
                                   'x-json' => {},
                                   'x-jsp' => {},
                                   'x-jsrender' => {},
                                   'x-julia' => {},
                                   'x-juttle' => {},
                                   'x-kconfig' => {},
                                   'x-koka' => {},
                                   'x-kom-basic' => {},
                                   'x-kotlin' => {},
                                   'x-ksh' => {},
                                   'x-la-asf' => {},
                                   'x-lasso' => {},
                                   'x-latex' => {},
                                   'x-ldif' => {},
                                   'x-lean' => {},
                                   'x-less' => {},
                                   'x-less-css' => {},
                                   'x-lex' => {},
                                   'x-libtool' => {},
                                   'x-lighttpd-conf' => {},
                                   'x-lilypond' => {},
                                   'x-literate-agda' => {},
                                   'x-literate-cryptol' => {},
                                   'x-literate-haskell' => {},
                                   'x-literate-idris' => {},
                                   'x-livescript' => {},
                                   'x-llvm' => {},
                                   'x-log' => {},
                                   'x-logos' => {},
                                   'x-logtalk' => {},
                                   'x-lsl' => {},
                                   'x-lua' => {},
                                   'x-lua-source' => {},
                                   'x-m' => {},
                                   'x-mail' => {},
                                   'x-makefile' => {},
                                   'x-mariadb' => {},
                                   'x-markdown' => {},
                                   'x-mask' => {},
                                   'x-mathematica' => {},
                                   'x-mathjax-config' => {},
                                   'x-mathml' => {},
                                   'x-matlab' => {},
                                   'x-mbl' => {},
                                   'x-mcf' => {},
                                   'x-meson' => {},
                                   'x-message-pem' => {
                                                      'params' => {
                                                                    'charset' => {}
                                                                  }
                                                    },
                                   'x-message-rfc1153' => {},
                                   'x-message-rfc934' => {},
                                   'x-microdvd' => {},
                                   'x-minidsrc' => {},
                                   'x-ml' => {},
                                   'x-mml' => {},
                                   'x-moc' => {},
                                   'x-modelica' => {},
                                   'x-modula' => {},
                                   'x-modula2' => {},
                                   'x-mof' => {},
                                   'x-monkey' => {},
                                   'x-moocode' => {},
                                   'x-moonscript' => {},
                                   'x-moz-deleted' => {},
                                   'x-moz-place' => {},
                                   'x-moz-place-container' => {},
                                   'x-moz-search-engine' => {},
                                   'x-moz-text-internal' => {},
                                   'x-moz-url' => {},
                                   'x-moz-url-data' => {},
                                   'x-moz-url-desc' => {},
                                   'x-moz-url-priv' => {},
                                   'x-mpsub' => {},
                                   'x-mql' => {},
                                   'x-mrm' => {},
                                   'x-mrml' => {},
                                   'x-ms-contact' => {},
                                   'x-ms-group' => {},
                                   'x-ms-iqy' => {},
                                   'x-ms-regedit' => {},
                                   'x-ms-rqy' => {},
                                   'x-mscgen' => {},
                                   'x-msgenny' => {},
                                   'x-msil' => {},
                                   'x-mssql' => {},
                                   'x-mup' => {},
                                   'x-mysql' => {},
                                   'x-nasm' => {},
                                   'x-nasm-objdump' => {},
                                   'x-nemerle' => {},
                                   'x-nescsrc' => {},
                                   'x-netrexx' => {},
                                   'x-newlisp' => {},
                                   'x-newspeak' => {},
                                   'x-nfo' => {},
                                   'x-nginx-conf' => {},
                                   'x-nif' => {},
                                   'x-nim' => {},
                                   'x-nix' => {},
                                   'x-nquads' => {},
                                   'x-nreum-data' => {},
                                   'x-nsis' => {},
                                   'x-objcsrc' => {},
                                   'x-objdump' => {},
                                   'x-objective-c' => {},
                                   'x-objective-c++' => {},
                                   'x-objective-j' => {},
                                   'x-objectivec' => {},
                                   'x-ocaml' => {},
                                   'x-ocl' => {},
                                   'x-octave' => {},
                                   'x-oeb1-css' => {},
                                   'x-oeb1-document' => {},
                                   'x-ooc' => {},
                                   'x-opa' => {},
                                   'x-openedge' => {},
                                   'x-opml' => {},
                                   'x-opml+xml' => {},
                                   'x-org' => {},
                                   'x-oz' => {},
                                   'x-packed-dat' => {},
                                   'x-parasail' => {},
                                   'x-pascal' => {},
                                   'x-patch' => {},
                                   'x-pawn' => {},
                                   'x-pcs-gcd' => {},
                                   'x-pdf' => {},
                                   'x-perl' => {
                                               'scripting_language' => 'yes'
                                             },
                                   'x-perl-script' => {},
                                   'x-perl6' => {},
                                   'x-perltt' => {},
                                   'x-perlxs' => {},
                                   'x-pgp-cleartext-signed' => {
                                                               'params' => {
                                                                             'charset' => {}
                                                                           }
                                                             },
                                   'x-pgsql' => {},
                                   'x-php' => {},
                                   'x-php-script' => {},
                                   'x-php-source' => {},
                                   'x-pig' => {},
                                   'x-pike' => {},
                                   'x-pkg-config' => {},
                                   'x-placeholder' => {},
                                   'x-plpgsql' => {},
                                   'x-plsql' => {},
                                   'x-pmaildx' => {},
                                   'x-po' => {},
                                   'x-pod' => {},
                                   'x-postgresql' => {},
                                   'x-postgresql-psql' => {},
                                   'x-pot' => {},
                                   'x-povray' => {},
                                   'x-powershell' => {},
                                   'x-pox' => {},
                                   'x-processing' => {},
                                   'x-prolog' => {},
                                   'x-properties' => {},
                                   'x-protobuf' => {},
                                   'x-psp' => {},
                                   'x-pug' => {},
                                   'x-puppet' => {},
                                   'x-python' => {},
                                   'x-python-doctest' => {},
                                   'x-python-script' => {},
                                   'x-python-traceback' => {},
                                   'x-python3' => {},
                                   'x-python3-traceback' => {},
                                   'x-q' => {},
                                   'x-qif' => {},
                                   'x-qml' => {},
                                   'x-r' => {},
                                   'x-r-doc' => {},
                                   'x-r-history' => {},
                                   'x-r-profile' => {},
                                   'x-r-source' => {},
                                   'x-racket' => {},
                                   'x-rat' => {},
                                   'x-rc' => {},
                                   'x-readme' => {},
                                   'x-rebol' => {},
                                   'x-red' => {},
                                   'x-red-system' => {},
                                   'x-regexp-js' => {},
                                   'x-reject' => {},
                                   'x-request-mfr' => {},
                                   'x-rexx' => {},
                                   'x-robotframework' => {},
                                   'x-roff' => {},
                                   'x-rpm-changes' => {},
                                   'x-rpm-spec' => {},
                                   'x-rql' => {},
                                   'x-rsrc' => {},
                                   'x-rst' => {},
                                   'x-rtf' => {
                                              'obsolete' => 1
                                            },
                                   'x-ruby' => {},
                                   'x-ruby-script' => {},
                                   'x-ruby-shellsession' => {},
                                   'x-rustsrc' => {},
                                   'x-safeframe' => {},
                                   'x-sas' => {},
                                   'x-sass' => {},
                                   'x-scala' => {},
                                   'x-scaml' => {},
                                   'x-scheme' => {},
                                   'x-scriplet' => {},
                                   'x-script' => {},
                                   'x-script-element-content' => {},
                                   'x-script-element-text' => {},
                                   'x-script-inline-documentation' => {},
                                   'x-script.csh' => {},
                                   'x-script.elisp' => {},
                                   'x-script.guile' => {},
                                   'x-script.ksh' => {},
                                   'x-script.lisp' => {},
                                   'x-script.perl' => {},
                                   'x-script.perl-module' => {},
                                   'x-script.phyton' => {},
                                   'x-script.python' => {},
                                   'x-script.rexx' => {},
                                   'x-script.ruby' => {},
                                   'x-script.scheme' => {},
                                   'x-script.sh' => {},
                                   'x-script.tcl' => {},
                                   'x-script.tcsh' => {},
                                   'x-script.zsh' => {},
                                   'x-scriptlet' => {},
                                   'x-scss' => {},
                                   'x-sed' => {},
                                   'x-serialization' => {},
                                   'x-server-parsed-html' => {},
                                   'x-server-parsed-html3' => {},
                                   'x-setext' => {},
                                   'x-sfv' => {},
                                   'x-sgml' => {},
                                   'x-sh' => {},
                                   'x-shellscript' => {},
                                   'x-shen' => {},
                                   'x-slim' => {},
                                   'x-sls' => {},
                                   'x-smalltalk' => {},
                                   'x-smarty' => {},
                                   'x-snobol' => {},
                                   'x-solr' => {},
                                   'x-sourcepawn' => {},
                                   'x-soy' => {},
                                   'x-speech' => {},
                                   'x-spreadsheet' => {},
                                   'x-sql' => {},
                                   'x-sqlite3-console' => {},
                                   'x-squidconf' => {},
                                   'x-squirrel' => {},
                                   'x-srt' => {},
                                   'x-ssa' => {},
                                   'x-standardml' => {},
                                   'x-stata' => {},
                                   'x-stex' => {},
                                   'x-stsrc' => {},
                                   'x-styl' => {},
                                   'x-subviewer' => {},
                                   'x-suikawiki' => {
                                                    'params' => {
                                                                  'version' => {}
                                                                }
                                                  },
                                   'x-suse-ymp' => {},
                                   'x-svhdr' => {},
                                   'x-svsrc' => {},
                                   'x-swift' => {},
                                   'x-syn' => {},
                                   'x-systemverilog' => {},
                                   'x-tab-separated-values' => {},
                                   'x-tasm' => {},
                                   'x-tcl' => {
                                              'scripting_language' => 'yes'
                                            },
                                   'x-tea' => {},
                                   'x-tex' => {},
                                   'x-texinfo' => {},
                                   'x-texmacs' => {},
                                   'x-textile' => {},
                                   'x-tiddlywiki' => {},
                                   'x-tika-text-based-message' => {},
                                   'x-tmpl' => {},
                                   'x-todo' => {},
                                   'x-toml' => {},
                                   'x-tornado' => {},
                                   'x-trac-wiki' => {},
                                   'x-troff' => {},
                                   'x-troff-man' => {},
                                   'x-troff-me' => {},
                                   'x-troff-mm' => {},
                                   'x-troff-ms' => {},
                                   'x-tsql' => {},
                                   'x-ttcn' => {},
                                   'x-ttcn-asn' => {},
                                   'x-ttcn-cfg' => {},
                                   'x-ttcn3' => {},
                                   'x-ttcnpp' => {},
                                   'x-ttml' => {},
                                   'x-txt2tags' => {},
                                   'x-typescript' => {},
                                   'x-typoscript' => {},
                                   'x-uil' => {},
                                   'x-underscore-template' => {},
                                   'x-uri' => {},
                                   'x-url' => {},
                                   'x-url-shortcut' => {
                                                       'params' => {
                                                                     'charset' => {}
                                                                   }
                                                     },
                                   'x-uuencode' => {},
                                   'x-vala' => {},
                                   'x-vb' => {},
                                   'x-vb-source' => {},
                                   'x-vba' => {},
                                   'x-vbasic' => {},
                                   'x-vbdotnet' => {},
                                   'x-vbnet' => {},
                                   'x-vbookmark' => {},
                                   'x-vbscript' => {
                                                   'scripting_language' => 'yes'
                                                 },
                                   'x-vcalendar' => {},
                                   'x-vcalender' => {},
                                   'x-vcard' => {},
                                   'x-vcf' => {},
                                   'x-vclsnippet' => {},
                                   'x-vclsrc' => {},
                                   'x-verilog' => {},
                                   'x-verilog-src' => {},
                                   'x-vertex' => {},
                                   'x-vhdl' => {},
                                   'x-vim' => {},
                                   'x-vmel' => {},
                                   'x-vmessage' => {},
                                   'x-vnd.flatland.3dml' => {
                                                            'obsolete' => 1
                                                          },
                                   'x-vnote' => {},
                                   'x-vtt' => {},
                                   'x-vue' => {},
                                   'x-wap-wta-wml' => {},
                                   'x-wap.wml' => {},
                                   'x-web-intelligent' => {},
                                   'x-web-markdown' => {},
                                   'x-webidl' => {},
                                   'x-webviewhtml' => {},
                                   'x-whiley' => {},
                                   'x-wiki' => {},
                                   'x-windows-registry' => {},
                                   'x-www-rules' => {},
                                   'x-x10' => {},
                                   'x-xetext' => {},
                                   'x-xmcd' => {},
                                   'x-xmi' => {},
                                   'x-xml' => {},
                                   'x-xslfo' => {},
                                   'x-xtend' => {},
                                   'x-xu' => {},
                                   'x-yacas' => {},
                                   'x-yacc' => {},
                                   'x-yaml' => {},
                                   'x-yaml+jinja' => {},
                                   'x-z80' => {},
                                   'x.suikawiki.image' => {
                                                          'params' => {
                                                                        'version' => {}
                                                                      }
                                                        },
                                   'x.wiki' => {},
                                   'xaml' => {},
                                   'xhtml' => {},
                                   'xhtml+xml' => {},
                                   'xml' => {
                                            'iana' => 'permanent',
                                            'iana_intended_usage' => 'common',
                                            'params' => {
                                                          'charset' => {
                                                                       'charset_rfc7303' => 1,
                                                                       'charset_xml' => 1
                                                                     },
                                                          'subtype' => {},
                                                          'version' => {
                                                                       'values' => {
                                                                                   '1.0' => {}
                                                                                 }
                                                                     }
                                                        },
                                            'scripting_language' => 'no',
                                            'text' => 1
                                          },
                                   'xml+oembed' => {},
                                   'xml-content' => {},
                                   'xml-dtd' => {},
                                   'xml-external-parsed-entity' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'common',
                                                                   'params' => {
                                                                                 'charset' => {
                                                                                              'charset_rfc7303' => 1,
                                                                                              'charset_xml' => 1
                                                                                            }
                                                                               }
                                                                 },
                                   'xml-script' => {
                                                   'scripting_language' => 'yes'
                                                 },
                                   'xml-soap' => {},
                                   'xmlp+xml' => {},
                                   'xmms-playlist' => {},
                                   'xquery' => {},
                                   'xsl' => {
                                            'params' => {
                                                          'charset' => {}
                                                        },
                                            'styling' => 1,
                                            'text' => 1
                                          },
                                   'xslfo' => {},
                                   'xul' => {
                                            'text' => 1
                                          },
                                   'yaml' => {}
                                 },
                    'text' => 1
                  },
          'ulead' => {
                     'subtype' => {
                                    'vrml' => {}
                                  }
                   },
          'unknown' => {
                       'subtype' => {
                                      'data' => {},
                                      'unknown' => {}
                                    }
                     },
          'vector' => {
                      'subtype' => {
                                     'x-dwg' => {},
                                     'x-dxf' => {},
                                     'x-svf' => {}
                                   }
                    },
          'video' => {
                     'audiovideo' => 1,
                     'iana' => 'permanent',
                     'not_script' => 1,
                     'subtype' => {
                                    '1d-interleaved-parityfec' => {
                                                                  'iana' => 'permanent',
                                                                  'iana_intended_usage' => 'common'
                                                                },
                                    '3gp' => {},
                                    '3gpp' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common',
                                              'params' => {
                                                            'codecs' => {}
                                                          }
                                            },
                                    '3gpp-tt' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    '3gpp2' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common',
                                               'params' => {
                                                             'codecs' => {}
                                                           }
                                             },
                                    'animaflex' => {},
                                    'avi' => {},
                                    'avs' => {},
                                    'avs-video' => {},
                                    'bmpeg' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                    'bt656' => {
                                               'iana' => 'permanent',
                                               'iana_intended_usage' => 'common'
                                             },
                                    'celb' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'daala' => {},
                                    'ditital-movie' => {},
                                    'divx' => {},
                                    'dl' => {
                                            'obsolete' => 1
                                          },
                                    'dv' => {
                                            'iana' => 'permanent',
                                            'iana_intended_usage' => 'common'
                                          },
                                    'dvb.mpeg.drip' => {},
                                    'encaprtp' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'limited use'
                                                },
                                    'example' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'limited use'
                                               },
                                    'flc' => {},
                                    'fli' => {},
                                    'flv' => {},
                                    'gl' => {
                                            'obsolete' => 1
                                          },
                                    'h261' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'h263' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'h263-1998' => {
                                                   'iana' => 'permanent'
                                                 },
                                    'h263-2000' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                    'h264' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'h264-rcdo' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                    'h264-svc' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    'h265' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'hypervideo' => {},
                                    'isivideo' => {},
                                    'iso.segment' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                    'jpeg' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'jpeg2000' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    'jpm' => {},
                                    'local' => {},
                                    'm2ts' => {},
                                    'm4v' => {},
                                    'mj2' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'mng' => {},
                                    'mp1s' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'mp2p' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'mp2t' => {
                                              'iana' => 'permanent',
                                              'iana_intended_usage' => 'common'
                                            },
                                    'mp4' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common',
                                             'params' => {
                                                           'codecs' => {}
                                                         }
                                           },
                                    'mp4v' => {},
                                    'mp4v-es' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'mpeg' => {
                                              'iana' => 'permanent'
                                            },
                                    'mpeg-2' => {},
                                    'mpeg-realtime' => {},
                                    'mpeg-system' => {},
                                    'mpeg2' => {},
                                    'mpeg4' => {},
                                    'mpeg4-generic' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'common'
                                                     },
                                    'mpg' => {},
                                    'mpv' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'msvideo' => {},
                                    'nv' => {
                                            'iana' => 'permanent',
                                            'iana_intended_usage' => 'common'
                                          },
                                    'ogg' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common',
                                             'params' => {
                                                           'codecs' => {}
                                                         }
                                           },
                                    'olivr' => {},
                                    'parityfec' => {
                                                   'iana' => 'permanent'
                                                 },
                                    'pointer' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'quicktime' => {
                                                   'iana' => 'permanent'
                                                 },
                                    'quicktime-stream' => {},
                                    'raptorfec' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                    'raw' => {
                                             'iana' => 'permanent'
                                           },
                                    'rtp-enc-aescm128' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                    'rtploopback' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'limited use'
                                                   },
                                    'rtx' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'sd-video' => {},
                                    'sgi-movie' => {},
                                    'smpte291' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    'smpte292m' => {
                                                   'iana' => 'permanent',
                                                   'iana_intended_usage' => 'common'
                                                 },
                                    'smtpe292m' => {},
                                    'theora' => {},
                                    'ulpfec' => {
                                                'iana' => 'permanent',
                                                'iana_intended_usage' => 'common'
                                              },
                                    'unknown' => {},
                                    'vc1' => {
                                             'iana' => 'permanent'
                                           },
                                    'vdo' => {},
                                    'vivo' => {},
                                    'vmx' => {},
                                    'vnd.avi' => {},
                                    'vnd.cctv' => {
                                                  'iana' => 'permanent',
                                                  'iana_intended_usage' => 'common'
                                                },
                                    'vnd.dece.hd' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                    'vnd.dece.mobile' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                    'vnd.dece.mp4' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'vnd.dece.pd' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                    'vnd.dece.sd' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                    'vnd.dece.video' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                    'vnd.directv.mpeg' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                    'vnd.directv.mpeg-tts' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                    'vnd.divx' => {},
                                    'vnd.dlna.mpeg-tts' => {
                                                           'iana' => 'permanent',
                                                           'iana_intended_usage' => 'common'
                                                         },
                                    'vnd.dvb.file' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'vnd.fvt' => {
                                                 'iana' => 'permanent',
                                                 'iana_intended_usage' => 'common'
                                               },
                                    'vnd.hns.video' => {
                                                       'iana' => 'permanent',
                                                       'iana_intended_usage' => 'limited use'
                                                     },
                                    'vnd.iptvforum.1dparityfec-1010' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                    'vnd.iptvforum.1dparityfec-2005' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                    'vnd.iptvforum.2dparityfec-1010' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                    'vnd.iptvforum.2dparityfec-2005' => {
                                                                        'iana' => 'permanent',
                                                                        'iana_intended_usage' => 'common'
                                                                      },
                                    'vnd.iptvforum.ttsavc' => {
                                                              'iana' => 'permanent',
                                                              'iana_intended_usage' => 'common'
                                                            },
                                    'vnd.iptvforum.ttsmpeg2' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                    'vnd.motorola.video' => {
                                                            'iana' => 'permanent'
                                                          },
                                    'vnd.motorola.videop' => {
                                                             'iana' => 'permanent'
                                                           },
                                    'vnd.mpegurl' => {
                                                     'iana' => 'permanent',
                                                     'iana_intended_usage' => 'common'
                                                   },
                                    'vnd.ms-playready.media.pyv' => {
                                                                    'iana' => 'permanent',
                                                                    'iana_intended_usage' => 'common'
                                                                  },
                                    'vnd.mts' => {},
                                    'vnd.nokia.interleaved-multimedia' => {
                                                                          'iana' => 'permanent',
                                                                          'iana_intended_usage' => 'limited use'
                                                                        },
                                    'vnd.nokia.mp4vr' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                    'vnd.nokia.videovoip' => {
                                                             'iana' => 'permanent',
                                                             'iana_intended_usage' => 'common'
                                                           },
                                    'vnd.objectvideo' => {
                                                         'iana' => 'permanent',
                                                         'iana_intended_usage' => 'common'
                                                       },
                                    'vnd.radgamettools.bink' => {
                                                                'iana' => 'permanent',
                                                                'iana_intended_usage' => 'common'
                                                              },
                                    'vnd.radgamettools.smacker' => {
                                                                   'iana' => 'permanent',
                                                                   'iana_intended_usage' => 'obsolete',
                                                                   'obsolete' => 1
                                                                 },
                                    'vnd.rn-realvideo' => {},
                                    'vnd.rn-realvideo-secure' => {},
                                    'vnd.sealed.mpeg1' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                    'vnd.sealed.mpeg4' => {
                                                          'iana' => 'permanent',
                                                          'iana_intended_usage' => 'common'
                                                        },
                                    'vnd.sealed.swf' => {
                                                        'iana' => 'permanent',
                                                        'iana_intended_usage' => 'common'
                                                      },
                                    'vnd.sealedmedia.softseal.mov' => {
                                                                      'iana' => 'permanent',
                                                                      'iana_intended_usage' => 'common'
                                                                    },
                                    'vnd.uvvu.mp4' => {
                                                      'iana' => 'permanent',
                                                      'iana_intended_usage' => 'common'
                                                    },
                                    'vnd.vivo' => {
                                                  'iana' => 'permanent'
                                                },
                                    'vosaic' => {},
                                    'vp8' => {
                                             'iana' => 'permanent',
                                             'iana_intended_usage' => 'common'
                                           },
                                    'wavelet' => {},
                                    'webm' => {},
                                    'x-acad-anim' => {},
                                    'x-amt-demorun' => {},
                                    'x-amt-showrun' => {},
                                    'x-anim' => {},
                                    'x-animaflex' => {},
                                    'x-annodex' => {},
                                    'x-arib-aiff' => {},
                                    'x-arib-avc' => {},
                                    'x-arib-hevc' => {},
                                    'x-arib-mng' => {},
                                    'x-arib-mpeg1' => {},
                                    'x-arib-mpeg2-aac' => {},
                                    'x-arib2-broadcast' => {},
                                    'x-atomic3d-feature' => {},
                                    'x-avi' => {},
                                    'x-avs-video' => {},
                                    'x-bamba' => {},
                                    'x-daala' => {},
                                    'x-dirac' => {},
                                    'x-divx' => {},
                                    'x-dl' => {},
                                    'x-dv' => {
                                              'obsolete' => 1
                                            },
                                    'x-example' => {},
                                    'x-f4v' => {},
                                    'x-flc' => {},
                                    'x-fli' => {},
                                    'x-flic' => {},
                                    'x-flv' => {
                                               'params' => {
                                                             'version' => {
                                                                          'values' => {
                                                                                      '1' => {}
                                                                                    }
                                                                        }
                                                           }
                                             },
                                    'x-gl' => {},
                                    'x-isivideo' => {},
                                    'x-isvideo' => {},
                                    'x-ivf' => {},
                                    'x-javafx' => {},
                                    'x-jng' => {},
                                    'x-jpm' => {},
                                    'x-la-asf' => {},
                                    'x-m4v' => {},
                                    'x-matroska' => {},
                                    'x-matroska-3d' => {},
                                    'x-mng' => {},
                                    'x-motion-jpeg' => {},
                                    'x-mpeg' => {},
                                    'x-mpeg-system' => {},
                                    'x-mpeg2' => {},
                                    'x-mpeg2a' => {},
                                    'x-mpeq2a' => {},
                                    'x-mpg' => {},
                                    'x-ms-asf' => {},
                                    'x-ms-asf-plugin' => {},
                                    'x-ms-asx' => {},
                                    'x-ms-vob' => {},
                                    'x-ms-wm' => {},
                                    'x-ms-wma' => {},
                                    'x-ms-wmd' => {},
                                    'x-ms-wmp' => {},
                                    'x-ms-wmv' => {},
                                    'x-ms-wmx' => {},
                                    'x-ms-wmz' => {},
                                    'x-ms-wvx' => {},
                                    'x-msvideo' => {},
                                    'x-msvideo-stream' => {},
                                    'x-mv' => {},
                                    'x-nficwmh263' => {},
                                    'x-nficwmjpeg' => {},
                                    'x-noa' => {},
                                    'x-nsv' => {},
                                    'x-ogg' => {},
                                    'x-ogg-rgb' => {},
                                    'x-ogg-uvs' => {},
                                    'x-ogg-yuv' => {},
                                    'x-oggrgb' => {},
                                    'x-ogguvs' => {},
                                    'x-oggyuv' => {},
                                    'x-ogm' => {},
                                    'x-ogm+ogg' => {},
                                    'x-pn-realvideo' => {},
                                    'x-qmsys' => {},
                                    'x-qtc' => {},
                                    'x-quicktime' => {},
                                    'x-raw' => {},
                                    'x-raw-yuv' => {},
                                    'x-scm' => {},
                                    'x-sgi-movie' => {},
                                    'x-sgi-video' => {},
                                    'x-smv' => {},
                                    'x-tango' => {},
                                    'x-theora' => {},
                                    'x-theora+ogg' => {},
                                    'x-totem-stream' => {},
                                    'x-unknown' => {},
                                    'x-vco' => {},
                                    'x-vcr' => {},
                                    'x-vdo' => {},
                                    'x-videogram' => {},
                                    'x-videogram-plugin' => {},
                                    'x-vif' => {},
                                    'x-vivo' => {},
                                    'x-vosaic' => {},
                                    'x-vps' => {},
                                    'x-wavelet' => {},
                                    'x-webm' => {},
                                    'x-webview-h' => {},
                                    'x-webview-p' => {},
                                    'xmpg2' => {},
                                    'youtube' => {}
                                  }
                   },
          'videotex' => {
                        'subtype' => {
                                       'vemmi' => {}
                                     }
                      },
          'vnd.afpc.afplinedata' => {
                                    'subtype' => {
                                                   '' => {}
                                                 }
                                  },
          'vnd.android.cursor.dir' => {
                                      'subtype' => {
                                                     'album' => {},
                                                     'artistalbum' => {},
                                                     'audio' => {},
                                                     'calls' => {},
                                                     'doc' => {},
                                                     'etc' => {},
                                                     'image' => {},
                                                     'nowplaying' => {},
                                                     'phone' => {},
                                                     'playlist' => {},
                                                     'track' => {},
                                                     'video' => {},
                                                     'vnd.google.inatproject' => {},
                                                     'vnd.google.note' => {},
                                                     'vnd.google.observation' => {},
                                                     'vnd.google.observation_photo' => {},
                                                     'vnd.google.projectobservation' => {},
                                                     'vnd.google.waypoint' => {},
                                                     'vnd.google.wikinote' => {},
                                                     'vnd.hatena.accounts' => {},
                                                     'vnd.iosched.session' => {},
                                                     'vnd.iosched.track' => {},
                                                     'vnd.iosched.vendor' => {}
                                                   }
                                    },
          'vnd.android.cursor.item' => {
                                       'subtype' => {
                                                      'calls' => {},
                                                      'phone' => {},
                                                      'vnd.google.inatproject' => {},
                                                      'vnd.google.note' => {},
                                                      'vnd.google.observation' => {},
                                                      'vnd.google.observation_photo' => {},
                                                      'vnd.google.projectobservation' => {},
                                                      'vnd.google.waypoint' => {},
                                                      'vnd.google.wikinote' => {},
                                                      'vnd.googleplus.profile.comm' => {},
                                                      'vnd.iosched.session' => {},
                                                      'vnd.iosched.vendor' => {}
                                                    }
                                     },
          'vnd.google.android.hangouts' => {
                                           'subtype' => {
                                                          'vnd.google.android.hangout_privileged' => {},
                                                          'vnd.google.android.hangout_whitelist' => {}
                                                        }
                                         },
          'vnd.google.fitness.activity_type' => {
                                                'subtype' => {
                                                               'running' => {}
                                                             }
                                              },
          'vnd.google.fitness.data_type' => {
                                            'subtype' => {
                                                           'com.example.my_type' => {},
                                                           'com.google.activity.segment' => {},
                                                           'com.google.heart_rate.bpm' => {},
                                                           'com.google.step_count.cumulative' => {},
                                                           'com.google.step_count.delta' => {}
                                                         }
                                          },
          'vnd.google.fitness.session' => {
                                          'subtype' => {
                                                         'biking' => {},
                                                         'running' => {}
                                                       }
                                        },
          'windows' => {
                       'subtype' => {
                                      'metafile' => {}
                                    }
                     },
          'windpws' => {
                       'subtype' => {
                                      'bitmap' => {}
                                    }
                     },
          'workbook' => {
                        'subtype' => {
                                       'formulaone' => {}
                                     }
                      },
          'world' => {
                     'subtype' => {
                                    'x-panoramix' => {}
                                  }
                   },
          'www' => {
                   'subtype' => {
                                  'mime' => {},
                                  'source' => {},
                                  'unknown' => {}
                                }
                 },
          'wwwserver' => {
                         'subtype' => {
                                        'redirection' => {}
                                      }
                       },
          'x-application' => {
                             'subtype' => {
                                            'aaa' => {},
                                            'file-mirror-list' => {},
                                            'framemaker' => {},
                                            'pdf' => {},
                                            'supercollider3' => {}
                                          }
                           },
          'x-chemical' => {
                          'subtype' => {
                                         'x-alchemy' => {},
                                         'x-cache' => {},
                                         'x-cache-csf' => {},
                                         'x-cactvs-binary' => {},
                                         'x-cdx' => {},
                                         'x-cerius' => {},
                                         'x-chem3d' => {},
                                         'x-chemdraw' => {},
                                         'x-cif' => {},
                                         'x-cmdf' => {},
                                         'x-cml' => {},
                                         'x-compass' => {},
                                         'x-crossfire' => {},
                                         'x-csml' => {},
                                         'x-ctx' => {},
                                         'x-cxf' => {},
                                         'x-embl-dl-nucleotide' => {},
                                         'x-galactic-spc' => {},
                                         'x-gamess-input' => {},
                                         'x-gaussian-checkpoint' => {},
                                         'x-gaussian-cube' => {},
                                         'x-gaussian-input' => {},
                                         'x-gaussian-log' => {},
                                         'x-gcg8-sequence' => {},
                                         'x-genbank' => {},
                                         'x-hin' => {},
                                         'x-isostar' => {},
                                         'x-jcamp-dx' => {},
                                         'x-kinemage' => {},
                                         'x-macmolecule' => {},
                                         'x-macromodel-input' => {},
                                         'x-mdl-molfile' => {},
                                         'x-mdl-rdfile' => {},
                                         'x-mdl-rxnfile' => {},
                                         'x-mdl-sdfile' => {},
                                         'x-mdl-tgf' => {},
                                         'x-mmcif' => {},
                                         'x-mol2' => {},
                                         'x-molconn-z' => {},
                                         'x-mopac-graph' => {},
                                         'x-mopac-input' => {},
                                         'x-mopac-out' => {},
                                         'x-mopac-vib' => {},
                                         'x-ncbi-asn1' => {},
                                         'x-ncbi-asn1-ascii' => {},
                                         'x-ncbi-asn1-binary' => {},
                                         'x-ncbi-asn1-spec' => {},
                                         'x-pdb' => {},
                                         'x-rosdal' => {},
                                         'x-swissprot' => {},
                                         'x-vamas-iso14976' => {},
                                         'x-vmd' => {},
                                         'x-xtel' => {},
                                         'x-xyz' => {}
                                       }
                        },
          'x-conference' => {
                            'subtype' => {
                                           'x-cooltalk' => {}
                                         }
                          },
          'x-content' => {
                         'subtype' => {
                                        'video-blueray' => {},
                                        'video-dvd' => {},
                                        'video-hddvd' => {},
                                        'video-svcd' => {},
                                        'video-vcd' => {},
                                        'x-audio-cdda' => {},
                                        'x-audio-dvd' => {},
                                        'x-audio-player' => {},
                                        'x-blank-bd' => {},
                                        'x-blank-cd' => {},
                                        'x-blank-dvd' => {},
                                        'x-blank-hddvd' => {},
                                        'x-ebook-reader' => {},
                                        'x-image-dcf' => {},
                                        'x-image-picturecd' => {},
                                        'x-software' => {},
                                        'x-unix-software' => {},
                                        'x-video-bluray' => {},
                                        'x-video-dvd' => {},
                                        'x-video-hddvd' => {},
                                        'x-video-svcd' => {},
                                        'x-video-vcd' => {},
                                        'x-win32-software' => {}
                                      }
                       },
          'x-data' => {
                      'subtype' => {
                                     'xact-error' => {}
                                   }
                    },
          'x-device' => {
                        'subtype' => {
                                       'floppy' => {}
                                     }
                      },
          'x-directory' => {
                           'subtype' => {
                                          'normal' => {}
                                        }
                         },
          'x-drawing' => {
                         'subtype' => {
                                        'dwf' => {},
                                        'x-dwf' => {}
                                      }
                       },
          'x-epoc' => {
                      'subtype' => {
                                     'x-sisx-app' => {}
                                   }
                    },
          'x-ferrum-head' => {
                             'subtype' => {
                                            'box' => {},
                                            'dict' => {}
                                          }
                           },
          'x-ferrum-menu' => {
                             'subtype' => {
                                            'cell' => {},
                                            'map' => {},
                                            'prop' => {}
                                          }
                           },
          'x-font' => {
                      'subtype' => {
                                     'eot' => {},
                                     'ttf' => {},
                                     'woff' => {},
                                     'x-opentype' => {}
                                   }
                    },
          'x-form' => {
                      'subtype' => {
                                     'x-openscape' => {}
                                   }
                    },
          'x-i-world' => {
                         'subtype' => {
                                        'x-i-vrml' => {}
                                      }
                       },
          'x-inode' => {
                       'subtype' => {
                                      'x-blockdevice' => {},
                                      'x-chardevice' => {},
                                      'x-directory' => {},
                                      'x-directory-locked' => {},
                                      'x-fifo' => {},
                                      'x-mount-point' => {},
                                      'x-socket' => {},
                                      'x-symlink' => {}
                                    }
                     },
          'x-jigsaw' => {
                        'subtype' => {
                                       'config' => {}
                                     }
                      },
          'x-kom' => {
                     'subtype' => {
                                    'basic' => {}
                                  }
                   },
          'x-lml' => {
                     'subtype' => {
                                    'x-evm' => {},
                                    'x-gdb' => {},
                                    'x-gps' => {},
                                    'x-lak' => {},
                                    'x-lml' => {},
                                    'x-lmlpack' => {},
                                    'x-ndb' => {}
                                  }
                   },
          'x-model' => {
                       'subtype' => {
                                      'x-mesh' => {}
                                    }
                     },
          'x-music' => {
                       'subtype' => {
                                      'x-crescendo' => {},
                                      'x-karaoke' => {},
                                      'x-midi' => {}
                                    }
                     },
          'x-paleovu' => {
                         'subtype' => {
                                        'x-pv' => {}
                                      }
                       },
          'x-pmaildx' => {
                         'subtype' => {
                                        'x-bandai' => {},
                                        'x-mmctrl' => {}
                                      }
                       },
          'x-postpet' => {
                         'subtype' => {
                                        'scrambled-effect-data' => {},
                                        'scrambled-model-data' => {},
                                        'scrambled-texture-data' => {}
                                      }
                       },
          'x-scheme-handler' => {
                                'subtype' => {
                                               'mms' => {},
                                               'mmsh' => {}
                                             }
                              },
          'x-script' => {
                        'subtype' => {
                                       'x-wfxscript' => {}
                                     }
                      },
          'x-shader' => {
                        'subtype' => {
                                       'x-fragment' => {},
                                       'x-vertex' => {}
                                     }
                      },
          'x-squid-internal' => {
                                'subtype' => {
                                               'vary' => {}
                                             }
                              },
          'x-system' => {
                        'subtype' => {
                                       'x-error' => {}
                                     }
                      },
          'x-text-pc' => {
                         'subtype' => {
                                        'ms-word' => {}
                                      }
                       },
          'x-unknown' => {
                         'subtype' => {
                                        'attachment' => {},
                                        'octet-stream' => {},
                                        'x-unknown' => {}
                                      }
                       },
          'x-visa-ii' => {
                         'subtype' => {
                                        'x-auth' => {}
                                      }
                       },
          'x-wap.multipart' => {
                               'subtype' => {
                                              'vnd.uplanet.header-set' => {}
                                            }
                             },
          'x-windows' => {
                         'subtype' => {
                                        'x-metafile' => {}
                                      }
                       },
          'x-world' => {
                       'subtype' => {
                                      'fx3d' => {},
                                      'realibase' => {},
                                      'x-3dmf' => {},
                                      'x-bitblaze' => {},
                                      'x-d96' => {},
                                      'x-svr' => {},
                                      'x-vream' => {},
                                      'x-vrml' => {},
                                      'x-vrml1.0' => {},
                                      'x-vrt' => {},
                                      'x-wvr' => {},
                                      'x-x3d' => {},
                                      'x-x3d+xml' => {},
                                      'x-x3d-vrml' => {},
                                      'x-xvr' => {}
                                    }
                     },
          'x-www' => {
                     'subtype' => {
                                    'x-mime' => {}
                                  }
                   },
          'x-xgl' => {
                     'subtype' => {
                                    'x-drawing' => {},
                                    'x-movie' => {}
                                  }
                   },
          'xgi' => {
                   'subtype' => {
                                  'drawing' => {},
                                  'movie' => {}
                                }
                 },
          'xgl' => {
                   'subtype' => {
                                  'drawing' => {},
                                  'movie' => {}
                                }
                 },
          'xml' => {
                   'subtype' => {
                                  'user-profile' => {},
                                  'x-wxformbuilder' => {}
                                }
                 },
          'zz-application' => {
                              'subtype' => {
                                             'zz-winassoc-tgz' => {}
                                           }
                            }
        };
$Web::MIME::_TypeDefs::Sniffing = {
          'archive' => [
                       [
                         qr/(?:\x1F\x8B\x08)/,
                         'application/x-gzip'
                       ],
                       [
                         qr/(?:Rar\x20\x1A\x07\x00)/,
                         'application/x-rar-compressed'
                       ],
                       [
                         qr/(?:PK\x03\x04)/,
                         'application/zip'
                       ]
                     ],
          'audio_or_video' => [
                              [
                                qr/(?:OggS\x00)/,
                                'application/ogg'
                              ],
                              [
                                qr/(?:FORM[\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF]AIFF)/,
                                'audio/aiff'
                              ],
                              [
                                qr/(?:\.snd)/,
                                'audio/basic'
                              ],
                              [
                                qr/(?:MThd\x00\x00\x00\x06)/,
                                'audio/midi'
                              ],
                              [
                                qr/(?:ID3)/,
                                'audio/mpeg'
                              ],
                              [
                                qr/(?:RIFF[\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF]WAVE)/,
                                'audio/wave'
                              ],
                              [
                                qr/(?:RIFF[\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF]AVI\x20)/,
                                'video/avi'
                              ]
                            ],
          'bom1' => [
                    [
                      qr/(?:(?:(?:\xFE\xFF|\xFF\xFE)[\x00-\xFF]|\xEF\xBB\xBF)[\x00-\xFF])/,
                      'text/plain'
                    ]
                  ],
          'bom2' => [
                    [
                      qr/(?:(?:\xEF\xBB\xBF|\xFE\xFF|\xFF\xFE))/,
                      'text/plain'
                    ]
                  ],
          'font' => [
                    [
                      qr/(?:[\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF]LP)/,
                      'application/vnd.ms-fontobject'
                    ],
                    [
                      qr/(?:ttcf)/,
                      'font/collection'
                    ],
                    [
                      qr/(?:OTTO)/,
                      'font/otf'
                    ],
                    [
                      qr/(?:\x00\x01\x00\x00)/,
                      'font/ttf'
                    ],
                    [
                      qr/(?:wOFF)/,
                      'font/woff'
                    ],
                    [
                      qr/(?:wOF2)/,
                      'font/woff2'
                    ]
                  ],
          'image' => [
                     [
                       qr/(?:BM)/,
                       'image/bmp'
                     ],
                     [
                       qr/(?:GIF8[79]a)/,
                       'image/gif'
                     ],
                     [
                       qr/(?:\xFF\xD8\xFF)/,
                       'image/jpeg'
                     ],
                     [
                       qr/(?:\x89PNG\x0D\x0A\x1A\x0A)/,
                       'image/png'
                     ],
                     [
                       qr/(?:RIFF[\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF]WEBPVP)/,
                       'image/webp'
                     ],
                     [
                       qr/(?:\x00\x00[\x01\x02]\x00)/,
                       'image/x-icon'
                     ]
                   ],
          'non_scriptable' => [
                              [
                                qr/(?:%!PS-Adobe-)/,
                                'application/postscript'
                              ]
                            ],
          'scriptable' => [
                          [
                            qr/(?:%PDF-)/,
                            'application/pdf'
                          ],
                          [
                            qr/(?:(?:[\x09\x0A\x0C\x0D\x20]*<(?:[Ss](?:[Cc][Rr][Ii][Pp][Tt][\x20>]|[Tt][Yy][Ll][Ee][\x20>])|[Tt](?:[Aa][Bb][Ll][Ee][\x20>]|[Ii][Tt][Ll][Ee][\x20>])|[Hh](?:[Ee][Aa][Dd][\x20>]|[Tt][Mm][Ll][\x20>]|1[\x20>])|[Bb](?:[\x20>]|[Oo][Dd][Yy][\x20>]|[Rr][\x20>])|[Ii][Ff][Rr][Aa][Mm][Ee][\x20>]|[Ff][Oo][Nn][Tt][\x20>]|[Dd][Ii][Vv][\x20>]|[Aa][\x20>]|[Pp][\x20>]|!--)|<![Dd][Oo][Cc][Tt][Yy][Pp][Ee]\x20[Hh][Tt][Mm][Ll][\x20>]))/,
                            'text/html'
                          ],
                          [
                            qr/(?:[\x09\x0A\x0C\x0D\x20]*<\?xml)/,
                            'text/xml'
                          ]
                        ],
          'text_track' => [
                          [
                            qr/(?:WEBVTT)/,
                            'text/vtt'
                          ]
                        ]
        };
$Web::MIME::_TypeDefs::MP3 = {
          'mp25rates' => [
                         0,
                         8000,
                         16000,
                         24000,
                         32000,
                         40000,
                         48000,
                         56000,
                         64000,
                         80000,
                         96000,
                         112000,
                         128000,
                         144000,
                         160000
                       ],
          'mp3rates' => [
                        0,
                        32000,
                        40000,
                        48000,
                        56000,
                        64000,
                        80000,
                        96000,
                        112000,
                        128000,
                        160000,
                        192000,
                        224000,
                        256000,
                        320000
                      ],
          'samplerates' => [
                           44100,
                           48000,
                           32000
                         ]
        };
1;
