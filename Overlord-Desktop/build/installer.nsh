; Custom NSIS include for Overlord Desktop installer

; Enable DPI awareness so the installer UI renders crisply on high-DPI displays
ManifestDPIAware true

!macro customInstall
  ; Create Start Menu shortcut
  CreateShortCut "$SMPROGRAMS\Overlord.lnk" "$INSTDIR\Overlord.exe" "" "$INSTDIR\Overlord.exe" 0
!macroend

!macro customUnInstall
  ; Remove Start Menu shortcut
  Delete "$SMPROGRAMS\Overlord.lnk"
!macroend
