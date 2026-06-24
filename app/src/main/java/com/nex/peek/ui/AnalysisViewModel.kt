package com.nex.peek.ui

import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.nex.peek.model.FunctionInfo

class AnalysisViewModel : ViewModel() {
    val selectedFunction = MutableLiveData<FunctionInfo?>()
}
